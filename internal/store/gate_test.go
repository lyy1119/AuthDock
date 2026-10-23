package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGateName(t *testing.T) {
	if err := ValidateGateName("日历"); err != nil {
		t.Fatalf("ValidateGateName(日历) = %v", err)
	}
	if err := ValidateGateName("  calendar  "); err != nil {
		t.Fatalf("ValidateGateName trims spaces: %v", err)
	}
	for _, value := range []string{"", "   ", strings.Repeat("x", 51), "bad\x00name"} {
		if err := ValidateGateName(value); err == nil {
			t.Errorf("ValidateGateName(%q) accepted an invalid name", value)
		}
	}
}

func TestValidateGateFrom(t *testing.T) {
	valid := []string{
		"10.0.0.1:1234",
		"10.0.0.1:10123",
		"http://10.0.0.1:1234",
		"https://service.internal:8443",
		"localhost:9000",
		"service.internal",
	}
	for _, value := range valid {
		if err := ValidateGateFrom(value); err != nil {
			t.Errorf("ValidateGateFrom(%q) = %v, want nil", value, err)
		}
	}
	invalid := []string{
		"",
		" 10.0.0.1:1234",
		"ftp://10.0.0.1",
		"http://",
		"http://user:pass@host",
		"with space",
		strings.Repeat("a", 256),
	}
	for _, value := range invalid {
		if err := ValidateGateFrom(value); err == nil {
			t.Errorf("ValidateGateFrom(%q) accepted an invalid upstream", value)
		}
	}
}

func TestNormalizeGateToPrefix(t *testing.T) {
	cases := map[string]string{
		"calendar": "calendar",
		"CALENDAR": "calendar",
		"team-1":   "team-1",
		"*":        "*",
		" cal ":    "cal",
	}
	for input, want := range cases {
		got, err := NormalizeGateToPrefix(input)
		if err != nil {
			t.Errorf("NormalizeGateToPrefix(%q) error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeGateToPrefix(%q) = %q, want %q", input, got, want)
		}
	}
	for _, value := range []string{"", "with.dot", "-lead", "trail-", "under_score", "汉字"} {
		if _, err := NormalizeGateToPrefix(value); err == nil {
			t.Errorf("NormalizeGateToPrefix(%q) accepted an invalid label", value)
		}
	}
}

func TestNormalizeGateToSuffix(t *testing.T) {
	cases := map[string]string{
		"":        "",
		"*":       "*",
		"app/":    "app/",
		"/app/":   "app/",
		" api/v1": "api/v1",
	}
	for input, want := range cases {
		got, err := NormalizeGateToSuffix(input)
		if err != nil {
			t.Errorf("NormalizeGateToSuffix(%q) error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeGateToSuffix(%q) = %q, want %q", input, got, want)
		}
	}
	for _, value := range []string{"with space", "tab\there", strings.Repeat("a", 256)} {
		if _, err := NormalizeGateToSuffix(value); err == nil {
			t.Errorf("NormalizeGateToSuffix(%q) accepted an invalid suffix", value)
		}
	}
}

func TestGateTarget(t *testing.T) {
	gate := Gate{ToPrefix: "calendar", ToSuffix: "app/"}
	if got := gate.Target("gw.example.net"); got != "https://calendar.gw.example.net/app/" {
		t.Fatalf("Target = %q", got)
	}
	gate = Gate{ToPrefix: "calendar"}
	if got := gate.Target("gw.example.net"); got != "https://calendar.gw.example.net/" {
		t.Fatalf("Target without suffix = %q", got)
	}
	if got := (Gate{ToPrefix: "calendar"}).Target(""); !strings.Contains(got, "未设置") {
		t.Fatalf("Target without domain = %q", got)
	}
}

func TestGateLifecycle(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	gate, err := db.CreateGate(ctx, "日历", "10.0.0.1:1234", "calendar", "app/", nil)
	if err != nil {
		t.Fatalf("CreateGate: %v", err)
	}
	if gate.ID == 0 || gate.Name != "日历" || gate.From != "10.0.0.1:1234" ||
		gate.ToPrefix != "calendar" || gate.ToSuffix != "app/" {
		t.Fatalf("unexpected gate %+v", gate)
	}

	gates, err := db.ListGates(ctx)
	if err != nil {
		t.Fatalf("ListGates: %v", err)
	}
	if len(gates) != 1 || gates[0].ID != gate.ID {
		t.Fatalf("ListGates = %+v", gates)
	}

	updated, err := db.UpdateGate(ctx, gate.ID, "新日历", "http://10.0.0.2:8080", "Cal", "/v1", nil)
	if err != nil {
		t.Fatalf("UpdateGate: %v", err)
	}
	if updated.Name != "新日历" || updated.From != "http://10.0.0.2:8080" ||
		updated.ToPrefix != "cal" || updated.ToSuffix != "v1" {
		t.Fatalf("gate not updated: %+v", updated)
	}

	if err := db.DeleteGate(ctx, gate.ID); err != nil {
		t.Fatalf("DeleteGate: %v", err)
	}
	if _, err := db.GetGate(ctx, gate.ID); !errors.Is(err, ErrGateNotFound) {
		t.Fatalf("GetGate after delete = %v, want ErrGateNotFound", err)
	}
	if err := db.DeleteGate(ctx, gate.ID); !errors.Is(err, ErrGateNotFound) {
		t.Fatalf("second DeleteGate = %v, want ErrGateNotFound", err)
	}
}

func TestCreateGateValidationAndConflicts(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if _, err := db.CreateGate(ctx, "", "10.0.0.1:1234", "calendar", "", nil); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := db.CreateGate(ctx, "日历", "ftp://10.0.0.1", "calendar", "", nil); err == nil {
		t.Fatal("ftp upstream accepted")
	}
	if _, err := db.CreateGate(ctx, "日历", "10.0.0.1:1234", "bad.label", "", nil); err == nil {
		t.Fatal("subdomain with a dot accepted")
	}

	if _, err := db.CreateGate(ctx, "日历", "10.0.0.1:1234", "calendar", "", nil); err != nil {
		t.Fatalf("CreateGate: %v", err)
	}
	if _, err := db.CreateGate(ctx, "重复", "10.0.0.2:1234", "calendar", "", nil); !errors.Is(err, ErrGateExists) {
		t.Fatalf("duplicate route = %v, want ErrGateExists", err)
	}
	// A different path prefix on the same subdomain is a different route.
	if _, err := db.CreateGate(ctx, "另一个", "10.0.0.2:1234", "calendar", "app/", nil); err != nil {
		t.Fatalf("second route on the same subdomain: %v", err)
	}
}

// TestMigrationDropsGatewayRules starts from the v2 schema and checks that
// opening the database replaces gateway_rules with the gate table.
func TestMigrationDropsGatewayRules(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "authdock.db")
	db := openTestStore(t, dbPath)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "admin", "adminpass1", RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Rewind to v2 to simulate a database from the previous release: drop every
	// table migration 3 and later created.
	for _, table := range []string{"gate", "sessions"} {
		if _, err := db.db.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
	if _, err := db.db.Exec(`CREATE TABLE gateway_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		subdomain TEXT NOT NULL,
		path TEXT NOT NULL DEFAULT '*',
		upstream TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("recreate gateway_rules: %v", err)
	}
	if _, err := db.db.Exec(`INSERT INTO gateway_rules (user_id, subdomain, path, upstream) VALUES (?, 'calendar', '*', 'http://old')`, admin.ID); err != nil {
		t.Fatalf("seed old rule: %v", err)
	}
	if _, err := db.db.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	db.db.Close()

	reopened, err := Open(dbPath, cheapHasher(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	gates, err := reopened.ListGates(ctx)
	if err != nil {
		t.Fatalf("ListGates after migration: %v", err)
	}
	if len(gates) != 0 {
		t.Fatalf("gate table should start empty, got %+v", gates)
	}
	var version int
	if err := reopened.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("user_version = %d, want %d", version, schemaVersion)
	}
	var oldTable int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gateway_rules'`).Scan(&oldTable); err != nil {
		t.Fatalf("inspect sqlite_master: %v", err)
	}
	if oldTable != 0 {
		t.Fatal("gateway_rules still exists after migration")
	}
}

func TestGateScope(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	alice, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	global, err := db.CreateGate(ctx, "全局", "10.0.0.1:1234", "global", "", nil)
	if err != nil {
		t.Fatalf("CreateGate(global): %v", err)
	}
	if global.UserID != nil || global.ScopeLabel() != "全局" {
		t.Fatalf("global gate = %+v", global)
	}

	scoped, err := db.CreateGate(ctx, "爱丽丝", "10.0.0.1:1234", "alice", "", &alice.ID)
	if err != nil {
		t.Fatalf("CreateGate(scoped): %v", err)
	}
	if scoped.UserID == nil || *scoped.UserID != alice.ID || scoped.Username != "alice" {
		t.Fatalf("scoped gate = %+v", scoped)
	}
	if scoped.ScopeLabel() != "alice" {
		t.Fatalf("ScopeLabel = %q", scoped.ScopeLabel())
	}

	// Switching a scoped gate back to global clears the owner.
	updated, err := db.UpdateGate(ctx, scoped.ID, scoped.Name, scoped.From, scoped.ToPrefix, scoped.ToSuffix, nil)
	if err != nil {
		t.Fatalf("UpdateGate(to global): %v", err)
	}
	if updated.UserID != nil {
		t.Fatalf("gate still scoped: %+v", updated)
	}

	// A gate scoped to a missing account is rejected.
	missing := int64(9999)
	if _, err := db.CreateGate(ctx, "x", "10.0.0.1:1234", "ghost", "", &missing); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("gate for an unknown user = %v, want ErrUserNotFound", err)
	}

	// Deleting the owner removes only its gates.
	if _, err := db.UpdateGate(ctx, scoped.ID, scoped.Name, scoped.From, scoped.ToPrefix, scoped.ToSuffix, &alice.ID); err != nil {
		t.Fatalf("UpdateGate(to alice): %v", err)
	}
	if err := db.DeleteUser(ctx, alice.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	gates, err := db.ListGates(ctx)
	if err != nil {
		t.Fatalf("ListGates: %v", err)
	}
	if len(gates) != 1 || gates[0].ID != global.ID {
		t.Fatalf("gates after owner deletion = %+v, want only the global gate", gates)
	}
}
