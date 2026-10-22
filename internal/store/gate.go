package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// ErrGateNotFound reports a gate lookup that matched no row.
	ErrGateNotFound = errors.New("store: gate not found")
	// ErrGateExists reports a (subdomain, path prefix) pair that is already taken.
	ErrGateExists = errors.New("store: this subdomain and path prefix already has a gate")
)

// Gate publishes one upstream service through the gateway domain.
//
// A request to
//
//	https://<ToPrefix>.<gateway domain>/<ToSuffix><rest>
//
// is forwarded to From/<rest>. ToPrefix is the subdomain label, ToSuffix the
// path prefix in front of the forwarded path, and From the upstream address
// such as "10.0.0.1:1234" or "http://10.0.0.1:1234".
type Gate struct {
	ID       int64
	Name     string
	From     string
	ToPrefix string
	ToSuffix string
	// UserID scopes the gate: nil means every account may use it, a value
	// restricts it to that account (whose name is in Username).
	UserID    *int64
	Username  string
	CreatedAt time.Time
}

// ScopeLabel renders the owner for the UI: 全局 or the account name.
func (g Gate) ScopeLabel() string {
	if g.UserID == nil || g.Username == "" {
		return "全局"
	}
	return g.Username
}

// Target renders the public URL of the gate for the given gateway domain.
func (g Gate) Target(domain string) string {
	if domain == "" {
		domain = "<网关域名未设置>"
	}
	suffix := ""
	if g.ToSuffix != "" {
		suffix = g.ToSuffix
	}
	return fmt.Sprintf("https://%s.%s/%s", g.ToPrefix, domain, suffix)
}

// ValidateGateName checks the human readable gate name.
func ValidateGateName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("store: gate name must not be empty")
	}
	if utf8.RuneCountInString(trimmed) > 50 {
		return errors.New("store: gate name must be at most 50 characters")
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return errors.New("store: gate name must not contain control characters")
		}
	}
	return nil
}

// ValidateGateFrom checks the upstream address, which may carry an http(s)
// scheme but defaults to plain http when the scheme is omitted.
func ValidateGateFrom(from string) error {
	if from == "" || strings.TrimSpace(from) != from {
		return errors.New("store: upstream must not be empty or carry surrounding spaces")
	}
	if len(from) > 255 {
		return errors.New("store: upstream must be at most 255 characters")
	}
	if strings.ContainsAny(from, " \t\r\n") {
		return errors.New("store: upstream must not contain whitespace")
	}

	candidate := from
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return fmt.Errorf("store: upstream is not a valid address: %w", err)
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("store: upstream scheme must be http or https")
	}
	if parsed.Host == "" {
		return errors.New("store: upstream must include a host")
	}
	if parsed.User != nil {
		return errors.New("store: upstream must not embed credentials")
	}
	return nil
}

// NormalizeGateToPrefix lowercases the subdomain label and validates it. The
// wildcard "*" is accepted so a gate can claim every subdomain.
func NormalizeGateToPrefix(prefix string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(prefix))
	if normalized == "*" {
		return normalized, nil
	}
	if normalized == "" || len(normalized) > 63 {
		return "", errors.New("store: subdomain must be 1-63 characters")
	}
	if strings.HasPrefix(normalized, "-") || strings.HasSuffix(normalized, "-") {
		return "", errors.New("store: subdomain must not start or end with a hyphen")
	}
	for i := 0; i < len(normalized); i++ {
		c := normalized[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return "", fmt.Errorf("store: subdomain contains unsupported character %q", c)
		}
	}
	return normalized, nil
}

// NormalizeGateToSuffix trims one leading slash and validates the path prefix
// that is inserted in front of the forwarded path. An empty suffix means the
// gate publishes the whole subdomain root.
func NormalizeGateToSuffix(suffix string) (string, error) {
	normalized := strings.TrimSpace(suffix)
	normalized = strings.TrimPrefix(normalized, "/")
	if normalized == "*" {
		return normalized, nil
	}
	if len(normalized) > 255 {
		return "", errors.New("store: path prefix must be at most 255 characters")
	}
	if strings.ContainsAny(normalized, " \t\r\n") {
		return "", errors.New("store: path prefix must not contain whitespace")
	}
	return normalized, nil
}

// ListGates returns every gate ordered by public route.
func (s *Store) ListGates(ctx context.Context) ([]Gate, error) {
	rows, err := s.db.QueryContext(ctx, gateSelect+` ORDER BY g.user_id IS NOT NULL, g.to_prefix, g.to_suffix, g.id`)
	if err != nil {
		return nil, fmt.Errorf("store: list gates: %w", err)
	}
	defer rows.Close()

	gates := make([]Gate, 0, 8)
	for rows.Next() {
		gate, err := scanGate(rows)
		if err != nil {
			return nil, err
		}
		gates = append(gates, gate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list gates: %w", err)
	}
	return gates, nil
}

// GetGate returns one gate by id.
func (s *Store) GetGate(ctx context.Context, id int64) (*Gate, error) {
	row := s.db.QueryRowContext(ctx, gateSelect+` WHERE g.id = ?`, id)

	gate, err := scanGate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGateNotFound
	}
	if err != nil {
		return nil, err
	}
	return &gate, nil
}

// CreateGate validates and inserts a gate. userID nil means the gate is global.
func (s *Store) CreateGate(ctx context.Context, name, from, toPrefix, toSuffix string, userID *int64) (*Gate, error) {
	cleanName, cleanFrom, cleanPrefix, cleanSuffix, err := normalizeGateInput(name, from, toPrefix, toSuffix)
	if err != nil {
		return nil, err
	}
	if userID != nil {
		if _, err := s.GetUserByID(ctx, *userID); err != nil {
			return nil, err
		}
	}

	result, err := s.db.ExecContext(ctx,
		`INSERT INTO gate (name, "from", to_prefix, to_suffix, user_id) VALUES (?, ?, ?, ?, ?)`,
		cleanName, cleanFrom, cleanPrefix, cleanSuffix, userID)
	if err != nil {
		return nil, wrapGateWriteError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: insert gate: %w", err)
	}
	s.restrictFiles()
	return s.GetGate(ctx, id)
}

// UpdateGate validates and rewrites a gate, including its scope.
func (s *Store) UpdateGate(ctx context.Context, id int64, name, from, toPrefix, toSuffix string, userID *int64) (*Gate, error) {
	if _, err := s.GetGate(ctx, id); err != nil {
		return nil, err
	}
	cleanName, cleanFrom, cleanPrefix, cleanSuffix, err := normalizeGateInput(name, from, toPrefix, toSuffix)
	if err != nil {
		return nil, err
	}
	if userID != nil {
		if _, err := s.GetUserByID(ctx, *userID); err != nil {
			return nil, err
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE gate SET name = ?, "from" = ?, to_prefix = ?, to_suffix = ?, user_id = ? WHERE id = ?`,
		cleanName, cleanFrom, cleanPrefix, cleanSuffix, userID, id); err != nil {
		return nil, wrapGateWriteError(err)
	}
	s.restrictFiles()
	return s.GetGate(ctx, id)
}

// DeleteGate removes a gate.
func (s *Store) DeleteGate(ctx context.Context, id int64) error {
	if _, err := s.GetGate(ctx, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM gate WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete gate: %w", err)
	}
	s.restrictFiles()
	return nil
}

func normalizeGateInput(name, from, toPrefix, toSuffix string) (string, string, string, string, error) {
	cleanName := strings.TrimSpace(name)
	if err := ValidateGateName(cleanName); err != nil {
		return "", "", "", "", err
	}
	cleanFrom := strings.TrimSpace(from)
	if err := ValidateGateFrom(cleanFrom); err != nil {
		return "", "", "", "", err
	}
	cleanPrefix, err := NormalizeGateToPrefix(toPrefix)
	if err != nil {
		return "", "", "", "", err
	}
	cleanSuffix, err := NormalizeGateToSuffix(toSuffix)
	if err != nil {
		return "", "", "", "", err
	}
	return cleanName, cleanFrom, cleanPrefix, cleanSuffix, nil
}

func wrapGateWriteError(err error) error {
	if isUniqueViolation(err) {
		return ErrGateExists
	}
	return fmt.Errorf("store: write gate: %w", err)
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

const gateSelect = `
SELECT g.id, g.name, g."from", g.to_prefix, g.to_suffix, g.user_id, COALESCE(u.username, ''), g.created_at
FROM gate g
LEFT JOIN users u ON u.id = g.user_id`

func scanGate(row rowScanner) (Gate, error) {
	var (
		gate      Gate
		userID    sql.NullInt64
		createdAt string
	)
	if err := row.Scan(&gate.ID, &gate.Name, &gate.From, &gate.ToPrefix, &gate.ToSuffix, &userID, &gate.Username, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Gate{}, err
		}
		return Gate{}, fmt.Errorf("store: scan gate: %w", err)
	}
	if userID.Valid {
		owner := userID.Int64
		gate.UserID = &owner
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		gate.CreatedAt = t
	}
	return gate, nil
}
