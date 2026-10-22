package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lyy1119/AuthDock/internal/passwd"
)

func cheapHasher(t *testing.T) *passwd.Hasher {
	t.Helper()
	hasher, err := passwd.NewHasher(passwd.Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return hasher
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	db, err := Open(path, cheapHasher(t))
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func countUsers(t *testing.T, db *Store) int {
	t.Helper()
	var count int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return count
}

func TestOpenCreatesSchemaAndPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "authdock.db")
	db := openTestStore(t, path)

	var version int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("user_version = %d, want %d", version, schemaVersion)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database file mode = %o, want 600", perm)
	}
}

func TestWriteKeepsSidecarFilesPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authdock.db")
	db := openTestStore(t, path)

	if _, _, err := db.SeedBootstrapAdmin(context.Background()); err != nil {
		t.Fatalf("SeedBootstrapAdmin: %v", err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue // sidecars appear only after SQLite writes
		}
		if err != nil {
			t.Fatalf("stat %q: %v", path+suffix, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", path+suffix, perm)
		}
	}
}

func TestSeedBootstrapAdminCreatesAdmin(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))

	password, created, err := db.SeedBootstrapAdmin(context.Background())
	if err != nil {
		t.Fatalf("SeedBootstrapAdmin: %v", err)
	}
	if !created {
		t.Fatal("SeedBootstrapAdmin did not report creating the admin account")
	}
	if len(password) != passwd.BootstrapPasswordLen {
		t.Fatalf("bootstrap password %q has length %d, want %d", password, len(password), passwd.BootstrapPasswordLen)
	}

	user, err := db.GetUserByUsername(context.Background(), BootstrapAdminUsername)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Fatalf("bootstrap role = %q, want %q", user.Role, RoleAdmin)
	}
	if !strings.HasPrefix(user.PasswordHash, "$argon2id$") {
		t.Fatalf("stored hash %q is not Argon2id", user.PasswordHash)
	}
	if err := db.VerifyPassword(user, password); err != nil {
		t.Fatalf("VerifyPassword with the generated password: %v", err)
	}
	if err := db.VerifyPassword(user, password+"x"); !errors.Is(err, passwd.ErrMismatch) {
		t.Fatalf("VerifyPassword with a wrong password = %v, want ErrMismatch", err)
	}
	if user.CreatedAt.IsZero() {
		t.Fatal("created_at was not parsed")
	}
	if got := countUsers(t, db); got != 1 {
		t.Fatalf("users table holds %d rows, want 1", got)
	}
}

func TestSeedBootstrapAdminIsIdempotent(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	firstPassword, created, err := db.SeedBootstrapAdmin(ctx)
	if err != nil || !created {
		t.Fatalf("first SeedBootstrapAdmin: created=%v err=%v", created, err)
	}

	password, created, err := db.SeedBootstrapAdmin(ctx)
	if err != nil {
		t.Fatalf("second SeedBootstrapAdmin: %v", err)
	}
	if created {
		t.Fatal("second SeedBootstrapAdmin created another account")
	}
	if password != "" {
		t.Fatalf("second SeedBootstrapAdmin returned a password %q, want none", password)
	}
	if got := countUsers(t, db); got != 1 {
		t.Fatalf("users table holds %d rows, want 1", got)
	}

	// The original password still works, so nothing was overwritten.
	user, err := db.GetUserByUsername(ctx, BootstrapAdminUsername)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if err := db.VerifyPassword(user, firstPassword); err != nil {
		t.Fatalf("original password stopped working: %v", err)
	}
}

func TestSeedBootstrapAdminSkipsNonEmptyTable(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "someone", "password123", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	password, created, err := db.SeedBootstrapAdmin(ctx)
	if err != nil {
		t.Fatalf("SeedBootstrapAdmin: %v", err)
	}
	if created || password != "" {
		t.Fatalf("SeedBootstrapAdmin created=%v password=%q, want no action", created, password)
	}
	if _, err := db.GetUserByUsername(ctx, BootstrapAdminUsername); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("admin lookup = %v, want ErrUserNotFound", err)
	}
}

func TestGetUserByUsername(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "alice", "password123", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	user, err := db.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user.Username != "alice" || user.Role != RoleUser || user.ID == 0 {
		t.Fatalf("unexpected user %+v", user)
	}

	// Usernames are case sensitive.
	if _, err := db.GetUserByUsername(ctx, "Alice"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetUserByUsername(Alice) = %v, want ErrUserNotFound", err)
	}
	if _, err := db.GetUserByUsername(ctx, "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetUserByUsername(nobody) = %v, want ErrUserNotFound", err)
	}
}

func TestCreateUserValidates(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, strings.Repeat("a", passwd.MaxUsernameLen+1), "password123", RoleUser); !errors.Is(err, passwd.ErrInvalidUsername) {
		t.Fatalf("21 character username = %v, want ErrInvalidUsername", err)
	}
	if _, err := db.CreateUser(ctx, "bob", "password123", "root"); err == nil {
		t.Fatal("role \"root\" was accepted")
	}
	if _, err := db.CreateUser(ctx, "bob", "", RoleUser); !errors.Is(err, passwd.ErrInvalidPassword) {
		t.Fatalf("empty password = %v, want ErrInvalidPassword", err)
	}
	if _, err := db.CreateUser(ctx, "bob", "password123", RoleUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := db.CreateUser(ctx, "bob", "password456", RoleUser); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate username = %v, want ErrUserExists", err)
	}
}

func TestSchemaConstraints(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))

	longName := strings.Repeat("a", passwd.MaxUsernameLen+1)
	if _, err := db.db.Exec(
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, longName, "hash", RoleUser,
	); err == nil {
		t.Fatal("users_username_len constraint did not reject a 21 character username")
	}

	if _, err := db.db.Exec(
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, "carol", "hash", "root",
	); err == nil {
		t.Fatal("users_role_valid constraint did not reject role \"root\"")
	}

	if _, err := db.db.Exec(
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, "dave", "hash", RoleUser,
	); err != nil {
		t.Fatalf("insert a valid row: %v", err)
	}
}

func TestPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authdock.db")
	ctx := context.Background()

	first := openTestStore(t, path)
	password, created, err := first.SeedBootstrapAdmin(ctx)
	if err != nil || !created {
		t.Fatalf("SeedBootstrapAdmin: created=%v err=%v", created, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(path, cheapHasher(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	if _, created, err := second.SeedBootstrapAdmin(ctx); err != nil || created {
		t.Fatalf("reopen SeedBootstrapAdmin: created=%v err=%v", created, err)
	}
	user, err := second.GetUserByUsername(ctx, BootstrapAdminUsername)
	if err != nil {
		t.Fatalf("GetUserByUsername after reopen: %v", err)
	}
	if err := second.VerifyPassword(user, password); err != nil {
		t.Fatalf("password does not verify after reopen: %v", err)
	}
}

func TestVerifyDummyDoesNotPanic(t *testing.T) {
	db := openTestStore(t, filepath.Join(t.TempDir(), "authdock.db"))

	db.VerifyDummy("whatever")
	db.VerifyDummy("whatever")
}

func TestOpenRequiresHasher(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "authdock.db"), nil); err == nil {
		t.Fatal("Open accepted a nil hasher")
	}
}

func TestInMemoryDatabase(t *testing.T) {
	db, err := Open(":memory:", cheapHasher(t))
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	defer db.Close()

	password, created, err := db.SeedBootstrapAdmin(context.Background())
	if err != nil || !created {
		t.Fatalf("SeedBootstrapAdmin on :memory: created=%v err=%v", created, err)
	}
	user, err := db.GetUserByUsername(context.Background(), BootstrapAdminUsername)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if err := db.VerifyPassword(user, password); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}
