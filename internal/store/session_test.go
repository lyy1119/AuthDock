package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

	expires := now.Add(12 * time.Hour)
	if err := db.CreateSession(ctx, ScopeAdmin, SessionKindAccess, "hash-alice", "alice", RoleUser, "", expires); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	session, ok, err := db.GetSession(ctx, ScopeAdmin, SessionKindAccess, "hash-alice", now)
	if err != nil || !ok {
		t.Fatalf("GetSession = %+v, %v, %v", session, ok, err)
	}
	if session.Username != "alice" || session.Role != RoleUser {
		t.Fatalf("session = %+v", session)
	}
	if !session.ExpiresAt.Equal(expires) {
		t.Fatalf("expires = %v, want %v", session.ExpiresAt, expires)
	}

	// Only the hash is stored: the raw token must not appear in the table.
	var stored string
	if err := db.db.QueryRow(`SELECT token_hash FROM sessions`).Scan(&stored); err != nil {
		t.Fatalf("read session row: %v", err)
	}
	if stored != "hash-alice" {
		t.Fatalf("stored token = %q", stored)
	}

	// Expired sessions disappear.
	if _, ok, _ := db.GetSession(ctx, ScopeAdmin, SessionKindAccess, "hash-alice", expires.Add(time.Minute)); ok {
		t.Fatal("an expired session was returned")
	}
	if _, ok, _ := db.GetSession(ctx, ScopeAdmin, SessionKindAccess, "hash-alice", now); ok {
		t.Fatal("the expired session was not cleaned up")
	}
}

func TestPruneSessions(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

	if err := db.CreateSession(ctx, ScopeGateway, SessionKindAccess, "old", "alice", RoleUser, "", now.Add(-time.Hour)); err != nil {
		t.Fatalf("CreateSession(old): %v", err)
	}
	if err := db.CreateSession(ctx, ScopeGateway, SessionKindAccess, "fresh", "bob", RoleUser, "", now.Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession(fresh): %v", err)
	}

	removed, err := db.PruneSessions(ctx, now)
	if err != nil {
		t.Fatalf("PruneSessions: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindAccess, "fresh", now); !ok {
		t.Fatal("the live session was pruned")
	}

	if err := db.DeleteSession(ctx, "fresh"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindAccess, "fresh", now); ok {
		t.Fatal("DeleteSession left the session behind")
	}
}

func TestGateRoutesMayRepeatPerScope(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	alice, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser(alice): %v", err)
	}
	bob, err := db.CreateUser(ctx, "bob", "bobpasswd1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser(bob): %v", err)
	}

	if _, err := db.CreateGate(ctx, "alice calendar", "10.0.0.1:1234", "calendar", "", &alice.ID); err != nil {
		t.Fatalf("alice gate: %v", err)
	}
	// The same public route, scoped to another account, is allowed.
	if _, err := db.CreateGate(ctx, "bob calendar", "10.0.0.2:1234", "calendar", "", &bob.ID); err != nil {
		t.Fatalf("bob gate on the same route: %v", err)
	}
	// A second gate with the same scope is not.
	if _, err := db.CreateGate(ctx, "alice again", "10.0.0.3:1234", "calendar", "", &alice.ID); err == nil {
		t.Fatal("a duplicate route for the same account was accepted")
	}
	// Global gates are unique among themselves.
	if _, err := db.CreateGate(ctx, "global", "10.0.0.4:1234", "calendar", "", nil); err != nil {
		t.Fatalf("global gate: %v", err)
	}
	if _, err := db.CreateGate(ctx, "global 2", "10.0.0.5:1234", "calendar", "", nil); err == nil {
		t.Fatal("a second global gate on the same route was accepted")
	}
}

func TestGatesForRouteOrdering(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	alice, err := db.CreateUser(ctx, "alice", "alicepass1", RoleUser)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	global, err := db.CreateGate(ctx, "global", "10.0.0.1:1234", "calendar", "", nil)
	if err != nil {
		t.Fatalf("global gate: %v", err)
	}
	scoped, err := db.CreateGate(ctx, "alice", "10.0.0.2:1234", "calendar", "", &alice.ID)
	if err != nil {
		t.Fatalf("scoped gate: %v", err)
	}
	wildcard, err := db.CreateGate(ctx, "wildcard", "10.0.0.3:1234", "*", "", nil)
	if err != nil {
		t.Fatalf("wildcard gate: %v", err)
	}

	gates, err := db.GatesForRoute(ctx, "calendar")
	if err != nil {
		t.Fatalf("GatesForRoute: %v", err)
	}
	if len(gates) != 3 {
		t.Fatalf("got %d candidates, want 3", len(gates))
	}
	if gates[0].ID != scoped.ID {
		t.Fatalf("first candidate = %q, want the account scoped one", gates[0].Name)
	}
	if gates[1].ID != global.ID {
		t.Fatalf("second candidate = %q, want the global one", gates[1].Name)
	}
	if gates[2].ID != wildcard.ID {
		t.Fatalf("third candidate = %q, want the wildcard last", gates[2].Name)
	}

	// An unknown label only matches the wildcard.
	other, err := db.GatesForRoute(ctx, "other")
	if err != nil {
		t.Fatalf("GatesForRoute(other): %v", err)
	}
	if len(other) != 1 || other[0].ID != wildcard.ID {
		t.Fatalf("candidates for other = %+v", other)
	}
}

// TestSessionScopesAreSeparate is the guarantee the two listeners rely on.
func TestSessionScopesAreSeparate(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)

	if err := db.CreateSession(ctx, ScopeAdmin, SessionKindAccess, "hash-boss", "boss", RoleAdmin, "", expires); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// The same token hash is only valid in the scope it was created for.
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindAccess, "hash-boss", now); ok {
		t.Fatal("an admin session was accepted in the gateway scope")
	}
	if _, ok, _ := db.GetSession(ctx, ScopeAdmin, SessionKindAccess, "hash-boss", now); !ok {
		t.Fatal("the admin session was not found in its own scope")
	}

	if err := db.CreateSession(ctx, "nonsense", SessionKindAccess, "hash-x", "alice", RoleUser, "", expires); err == nil {
		t.Fatal("CreateSession accepted an unknown scope")
	}
}

func TestRotateRefreshSession(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

	if err := db.CreateSession(ctx, ScopeGateway, SessionKindRefresh, "refresh-1", "alice", RoleUser, "family-1", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	session, ok, err := db.RotateRefreshSession(ctx, ScopeGateway,
		"refresh-1", "refresh-2", "access-2", now.Add(time.Hour), now.Add(48*time.Hour), now)
	if err != nil || !ok {
		t.Fatalf("RotateRefreshSession = %v, %v", ok, err)
	}
	if session.Username != "alice" || session.Family != "family-1" {
		t.Fatalf("rotated session = %+v", session)
	}

	// The presented refresh token is consumed exactly once.
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindRefresh, "refresh-1", now); ok {
		t.Fatal("the old refresh token is still usable")
	}
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindRefresh, "refresh-2", now); !ok {
		t.Fatal("the new refresh token is missing")
	}
	if _, ok, _ := db.GetSession(ctx, ScopeGateway, SessionKindAccess, "access-2", now); !ok {
		t.Fatal("the new access token is missing")
	}

	// Replaying the consumed token fails without issuing anything.
	if _, ok, _ := db.RotateRefreshSession(ctx, ScopeGateway,
		"refresh-1", "refresh-3", "access-3", now.Add(time.Hour), now.Add(48*time.Hour), now); ok {
		t.Fatal("a consumed refresh token was accepted")
	}

	// Revoking the family drops both kinds.
	if err := db.RevokeSessionFamily(ctx, "access-2"); err != nil {
		t.Fatalf("RevokeSessionFamily: %v", err)
	}
	for _, probe := range []struct{ kind, hash string }{
		{SessionKindAccess, "access-2"},
		{SessionKindRefresh, "refresh-2"},
	} {
		if _, ok, _ := db.GetSession(ctx, ScopeGateway, probe.kind, probe.hash, now); ok {
			t.Fatalf("%s/%s survived the family revocation", probe.kind, probe.hash)
		}
	}
}

func TestExpiredRefreshSessionIsRejected(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

	if err := db.CreateSession(ctx, ScopeGateway, SessionKindRefresh, "refresh-old", "alice", RoleUser, "", now.Add(-time.Minute)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, ok, err := db.RotateRefreshSession(ctx, ScopeGateway,
		"refresh-old", "refresh-new", "access-new", now.Add(time.Hour), now.Add(48*time.Hour), now); ok || err != nil {
		t.Fatalf("expired refresh = %v, %v; want rejected without error", ok, err)
	}
}
