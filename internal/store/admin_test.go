package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lyy1119/AuthDock/internal/passwd"
)

func TestListUsers(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if _, _, err := db.SeedBootstrapAdmin(ctx); err != nil {
		t.Fatalf("SeedBootstrapAdmin: %v", err)
	}
	if _, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	users, err := db.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("ListUsers returned %d users, want 2", len(users))
	}
	if users[0].Username != BootstrapAdminUsername || users[1].Username != "alice" {
		t.Fatalf("unexpected order: %q, %q", users[0].Username, users[1].Username)
	}
	if users[1].Role != RoleUser {
		t.Fatalf("alice role = %q, want %q", users[1].Role, RoleUser)
	}
}

func TestUpdateUserRole(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	alice, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	updated, err := db.UpdateUserRole(ctx, alice.ID, RoleAdmin)
	if err != nil {
		t.Fatalf("UpdateUserRole: %v", err)
	}
	if updated.Role != RoleAdmin {
		t.Fatalf("role = %q, want %q", updated.Role, RoleAdmin)
	}

	if _, err := db.UpdateUserRole(ctx, alice.ID, "root"); err == nil {
		t.Fatal("UpdateUserRole accepted an unknown role")
	}
	if _, err := db.UpdateUserRole(ctx, 9999, RoleUser); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("UpdateUserRole(unknown) = %v, want ErrUserNotFound", err)
	}
}

func TestSetUserPassword(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	updated, err := db.SetUserPassword(ctx, user.ID, "brand-new-pass1")
	if err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if err := db.VerifyPassword(updated, "brand-new-pass1"); err != nil {
		t.Fatalf("new password does not verify: %v", err)
	}
	if err := db.VerifyPassword(updated, "alicepass1"); !errors.Is(err, passwd.ErrMismatch) {
		t.Fatalf("old password still verifies: %v", err)
	}

	if _, err := db.SetUserPassword(ctx, user.ID, "short"); !errors.Is(err, passwd.ErrInvalidPassword) {
		t.Fatalf("short password accepted: %v", err)
	}
	if _, err := db.SetUserPassword(ctx, 9999, "brand-new-pass1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("SetUserPassword(unknown) = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteUserLeavesGatesAlone(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	alice, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := db.CreateGate(ctx, "日历", "10.0.0.1:1234", "calendar", ""); err != nil {
		t.Fatalf("CreateGate: %v", err)
	}
	if err := db.DeleteUser(ctx, alice.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := db.GetUserByID(ctx, alice.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("user still present after delete: %v", err)
	}
	gates, err := db.ListGates(ctx)
	if err != nil {
		t.Fatalf("ListGates: %v", err)
	}
	if len(gates) != 1 {
		t.Fatalf("gates = %+v, want the gate to survive a user deletion", gates)
	}
	if err := db.DeleteUser(ctx, alice.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("second DeleteUser = %v, want ErrUserNotFound", err)
	}
}

func TestCountAdmins(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if got, err := db.CountAdmins(ctx); err != nil || got != 0 {
		t.Fatalf("CountAdmins on empty table = %d, %v", got, err)
	}
	if _, _, err := db.SeedBootstrapAdmin(ctx); err != nil {
		t.Fatalf("SeedBootstrapAdmin: %v", err)
	}
	if got, err := db.CountAdmins(ctx); err != nil || got != 1 {
		t.Fatalf("CountAdmins = %d, %v; want 1", got, err)
	}
	if _, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got, err := db.CountAdmins(ctx); err != nil || got != 1 {
		t.Fatalf("CountAdmins after a user account = %d, %v; want 1", got, err)
	}
}

func TestSettings(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if value, err := db.Setting(ctx, SettingsKeyGatewayDomain); err != nil || value != "" {
		t.Fatalf("unset setting = %q, %v; want empty", value, err)
	}
	if err := db.SetSetting(ctx, SettingsKeyGatewayDomain, "gw.example.net"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if value, err := db.Setting(ctx, SettingsKeyGatewayDomain); err != nil || value != "gw.example.net" {
		t.Fatalf("stored setting = %q, %v", value, err)
	}
	if err := db.SetSetting(ctx, SettingsKeyGatewayDomain, "gw.other.net"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}
	if value, _ := db.Setting(ctx, SettingsKeyGatewayDomain); value != "gw.other.net" {
		t.Fatalf("overwritten setting = %q, want gw.other.net", value)
	}
}

// TestMigrateFromVersion1 starts from a database that only has the v1 schema and
// checks that opening it upgrades to the current version without losing rows.
func TestMigrateFromVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authdock.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	if _, err := raw.Exec(migrations[0]); err != nil {
		t.Fatalf("apply v1 schema: %v", err)
	}
	if _, err := raw.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO users (username, password_hash, role) VALUES ('legacy', 'x', 'admin')`); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw database: %v", err)
	}

	db := openTestStore(t, path)
	ctx := context.Background()

	var version int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("user_version = %d, want %d", version, schemaVersion)
	}
	if _, err := db.GetUserByUsername(ctx, "legacy"); err != nil {
		t.Fatalf("legacy user lost during migration: %v", err)
	}
	if _, err := db.Setting(ctx, SettingsKeyGatewayDomain); err != nil {
		t.Fatalf("settings table missing after migration: %v", err)
	}
	if _, err := db.ListGates(ctx); err != nil {
		t.Fatalf("gate table missing after migration: %v", err)
	}
}
