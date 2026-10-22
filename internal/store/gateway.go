package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrRuleNotFound reports a gateway rule lookup that matched no row.
var ErrRuleNotFound = errors.New("store: gateway rule not found")

// GatewayRule routes requests for one subdomain (and path pattern) of the
// gateway domain to an upstream URL.
type GatewayRule struct {
	ID        int64
	UserID    int64
	Username  string
	Subdomain string
	Path      string
	Upstream  string
	CreatedAt time.Time
}

// ValidateSubdomain accepts a single DNS label or the wildcard "*".
func ValidateSubdomain(subdomain string) error {
	if subdomain == "*" {
		return nil
	}
	if subdomain == "" || len(subdomain) > 63 {
		return fmt.Errorf("store: subdomain must be 1-63 characters")
	}
	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return fmt.Errorf("store: subdomain must not start or end with a hyphen")
	}
	for i := 0; i < len(subdomain); i++ {
		c := subdomain[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("store: subdomain contains unsupported character %q", c)
		}
	}
	return nil
}

// ValidatePath accepts the wildcard "*" or an absolute path starting with "/".
func ValidatePath(path string) error {
	if path == "*" {
		return nil
	}
	if path == "" || len(path) > 255 {
		return fmt.Errorf("store: path must be 1-255 characters")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("store: path must start with /")
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("store: path must not contain whitespace")
	}
	return nil
}

// ValidateUpstream accepts an absolute http(s) URL with a host and no embedded
// credentials.
func ValidateUpstream(upstream string) error {
	if upstream == "" || len(upstream) > 2048 {
		return fmt.Errorf("store: upstream must be 1-2048 characters")
	}
	parsed, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("store: upstream is not a valid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("store: upstream scheme must be http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("store: upstream must include a host")
	}
	if parsed.User != nil {
		return fmt.Errorf("store: upstream must not embed credentials")
	}
	return nil
}

// ValidateGatewayDomain accepts "" (not configured) or a bare DNS name such as
// "gw.example.net". A scheme, port, path or whitespace is rejected.
func ValidateGatewayDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if len(domain) > 253 {
		return fmt.Errorf("store: gateway domain is too long")
	}
	if strings.ContainsAny(domain, "/:@ \t\r\n") {
		return fmt.Errorf("store: gateway domain must be a bare host name")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("store: gateway domain has an empty or overlong label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("store: gateway domain labels must not start or end with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return fmt.Errorf("store: gateway domain contains unsupported character %q", c)
			}
		}
	}
	return nil
}

// ListGatewayRules returns every rule joined with its owner's username.
func (s *Store) ListGatewayRules(ctx context.Context) ([]GatewayRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.user_id, u.username, r.subdomain, r.path, r.upstream, r.created_at
		FROM gateway_rules r
		JOIN users u ON u.id = r.user_id
		ORDER BY r.user_id, r.id`)
	if err != nil {
		return nil, fmt.Errorf("store: list gateway rules: %w", err)
	}
	defer rows.Close()

	rules := make([]GatewayRule, 0, 8)
	for rows.Next() {
		rule, err := scanGatewayRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list gateway rules: %w", err)
	}
	return rules, nil
}

// GetGatewayRule returns one rule by id.
func (s *Store) GetGatewayRule(ctx context.Context, id int64) (*GatewayRule, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT r.id, r.user_id, u.username, r.subdomain, r.path, r.upstream, r.created_at
		FROM gateway_rules r
		JOIN users u ON u.id = r.user_id
		WHERE r.id = ?`, id)

	rule, err := scanGatewayRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRuleNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// CreateGatewayRule validates and inserts a rule for userID.
func (s *Store) CreateGatewayRule(ctx context.Context, userID int64, subdomain, path, upstream string) (*GatewayRule, error) {
	if _, err := s.GetUserByID(ctx, userID); err != nil {
		return nil, err
	}
	if err := validateRuleFields(subdomain, path, upstream); err != nil {
		return nil, err
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO gateway_rules (user_id, subdomain, path, upstream) VALUES (?, ?, ?, ?)`,
		userID, subdomain, path, upstream)
	if err != nil {
		return nil, fmt.Errorf("store: insert gateway rule: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: insert gateway rule: %w", err)
	}
	s.restrictFiles()
	return s.GetGatewayRule(ctx, id)
}

// UpdateGatewayRule validates and rewrites the three editable fields of a rule.
func (s *Store) UpdateGatewayRule(ctx context.Context, id int64, subdomain, path, upstream string) (*GatewayRule, error) {
	if _, err := s.GetGatewayRule(ctx, id); err != nil {
		return nil, err
	}
	if err := validateRuleFields(subdomain, path, upstream); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE gateway_rules SET subdomain = ?, path = ?, upstream = ? WHERE id = ?`,
		subdomain, path, upstream, id); err != nil {
		return nil, fmt.Errorf("store: update gateway rule: %w", err)
	}
	s.restrictFiles()
	return s.GetGatewayRule(ctx, id)
}

// DeleteGatewayRule removes a rule.
func (s *Store) DeleteGatewayRule(ctx context.Context, id int64) error {
	if _, err := s.GetGatewayRule(ctx, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM gateway_rules WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete gateway rule: %w", err)
	}
	s.restrictFiles()
	return nil
}

func validateRuleFields(subdomain, path, upstream string) error {
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	return ValidateUpstream(upstream)
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanGatewayRule(row rowScanner) (GatewayRule, error) {
	var (
		rule      GatewayRule
		createdAt string
	)
	if err := row.Scan(&rule.ID, &rule.UserID, &rule.Username, &rule.Subdomain, &rule.Path, &rule.Upstream, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GatewayRule{}, err
		}
		return GatewayRule{}, fmt.Errorf("store: scan gateway rule: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		rule.CreatedAt = t
	}
	return rule, nil
}
