package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestValidateSubdomain(t *testing.T) {
	valid := []string{"calendar", "*", "team-calendar", "a", "USER1", "x1-y2"}
	for _, value := range valid {
		if err := ValidateSubdomain(value); err != nil {
			t.Errorf("ValidateSubdomain(%q) = %v, want nil", value, err)
		}
	}
	invalid := []string{"", "with.dot", "with space", "-lead", "trail-", "under_score", "汉字", "a*"}
	for _, value := range invalid {
		if err := ValidateSubdomain(value); err == nil {
			t.Errorf("ValidateSubdomain(%q) accepted an invalid value", value)
		}
	}
}

func TestValidatePath(t *testing.T) {
	valid := []string{"*", "/", "/api", "/api/v1", "/files/"}
	for _, value := range valid {
		if err := ValidatePath(value); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", value, err)
		}
	}
	invalid := []string{"", "api", "api/v1", "/with space", "/tab\t"}
	for _, value := range invalid {
		if err := ValidatePath(value); err == nil {
			t.Errorf("ValidatePath(%q) accepted an invalid value", value)
		}
	}
}

func TestValidateUpstream(t *testing.T) {
	valid := []string{
		"http://10.0.0.1:10123/",
		"https://example.com",
		"http://127.0.0.1:9000/base/",
	}
	for _, value := range valid {
		if err := ValidateUpstream(value); err != nil {
			t.Errorf("ValidateUpstream(%q) = %v, want nil", value, err)
		}
	}
	invalid := []string{
		"",
		"example.com",
		"ftp://example.com",
		"http://",
		"//example.com",
		"http://user:pass@example.com",
		"not a url",
	}
	for _, value := range invalid {
		if err := ValidateUpstream(value); err == nil {
			t.Errorf("ValidateUpstream(%q) accepted an invalid value", value)
		}
	}
}

func TestValidateGatewayDomain(t *testing.T) {
	valid := []string{"", "gw.example.net", "example.com", "a-b.c"}
	for _, value := range valid {
		if err := ValidateGatewayDomain(value); err != nil {
			t.Errorf("ValidateGatewayDomain(%q) = %v, want nil", value, err)
		}
	}
	invalid := []string{"https://gw.example.net", "gw.example.net/", "gw.example.net:8080", "gw..net", ".gw.net", "-gw.net", "gw net"}
	for _, value := range invalid {
		if err := ValidateGatewayDomain(value); err == nil {
			t.Errorf("ValidateGatewayDomain(%q) accepted an invalid value", value)
		}
	}
}

func TestGatewayRuleLifecycle(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "admin", "adminpass1", RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rule, err := db.CreateGatewayRule(ctx, admin.ID, "calendar", "*", "http://10.0.0.1:10123/")
	if err != nil {
		t.Fatalf("CreateGatewayRule: %v", err)
	}
	if rule.ID == 0 || rule.Username != "admin" || rule.UserID != admin.ID {
		t.Fatalf("unexpected rule %+v", rule)
	}

	rules, err := db.ListGatewayRules(ctx)
	if err != nil {
		t.Fatalf("ListGatewayRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("ListGatewayRules = %+v", rules)
	}

	updated, err := db.UpdateGatewayRule(ctx, rule.ID, "*", "/api", "http://127.0.0.1:9000/")
	if err != nil {
		t.Fatalf("UpdateGatewayRule: %v", err)
	}
	if updated.Subdomain != "*" || updated.Path != "/api" || updated.Upstream != "http://127.0.0.1:9000/" {
		t.Fatalf("rule not updated: %+v", updated)
	}

	if err := db.DeleteGatewayRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteGatewayRule: %v", err)
	}
	if _, err := db.GetGatewayRule(ctx, rule.ID); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("GetGatewayRule after delete = %v, want ErrRuleNotFound", err)
	}
	if rules, _ := db.ListGatewayRules(ctx); len(rules) != 0 {
		t.Fatalf("rules remain after delete: %+v", rules)
	}
}

func TestCreateGatewayRuleValidates(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "admin", "adminpass1", RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := db.CreateGatewayRule(ctx, 9999, "calendar", "*", "http://127.0.0.1:9000/"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("rule for unknown user = %v, want ErrUserNotFound", err)
	}
	if _, err := db.CreateGatewayRule(ctx, admin.ID, "bad domain", "*", "http://127.0.0.1:9000/"); err == nil {
		t.Fatal("invalid subdomain accepted")
	}
	if _, err := db.CreateGatewayRule(ctx, admin.ID, "calendar", "api", "http://127.0.0.1:9000/"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := db.CreateGatewayRule(ctx, admin.ID, "calendar", "*", "ftp://127.0.0.1/"); err == nil {
		t.Fatal("non-http upstream accepted")
	}
	if _, err := db.UpdateGatewayRule(ctx, 9999, "calendar", "*", "http://127.0.0.1:9000/"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("update of unknown rule = %v, want ErrRuleNotFound", err)
	}
	if err := db.DeleteGatewayRule(ctx, 9999); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("delete of unknown rule = %v, want ErrRuleNotFound", err)
	}
}
