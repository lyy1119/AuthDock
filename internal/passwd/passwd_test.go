package passwd_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/lyy1119/AuthDock/internal/passwd"
)

// testParams keep the unit tests fast: the cheapest parameters the package
// accepts still exercise the same code paths.
func testParams() passwd.Params {
	return passwd.Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func testHasher(t *testing.T) *passwd.Hasher {
	t.Helper()
	hasher, err := passwd.NewHasher(testParams())
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return hasher
}

func TestHashVerifyRoundTrip(t *testing.T) {
	hasher := testHasher(t)
	const password = "correct horse battery staple"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := hasher.Verify(password, hash); err != nil {
		t.Fatalf("Verify with the right password: %v", err)
	}
	if err := hasher.Verify(password+"!", hash); !errors.Is(err, passwd.ErrMismatch) {
		t.Fatalf("Verify with a wrong password = %v, want ErrMismatch", err)
	}
}

func TestHashFormat(t *testing.T) {
	hasher := testHasher(t)

	hash, err := hasher.Hash("hunter2-with-some-length")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	const prefix = "$argon2id$v=19$m=8192,t=1,p=1$"
	if !strings.HasPrefix(hash, prefix) {
		t.Fatalf("hash = %q, want prefix %q", hash, prefix)
	}
	if parts := strings.Split(hash, "$"); len(parts) != 6 {
		t.Fatalf("hash has %d $-separated fields, want 6", len(parts))
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	hasher := testHasher(t)

	first, err := hasher.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := hasher.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are identical, salt is not random")
	}
	for _, hash := range []string{first, second} {
		if err := hasher.Verify("same-password", hash); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

func TestHashRejectsUnusablePasswords(t *testing.T) {
	hasher := testHasher(t)

	if _, err := hasher.Hash(""); !errors.Is(err, passwd.ErrInvalidPassword) {
		t.Fatalf("Hash(\"\") = %v, want ErrInvalidPassword", err)
	}
	tooLong := strings.Repeat("a", passwd.MaxPasswordLen+1)
	if _, err := hasher.Hash(tooLong); !errors.Is(err, passwd.ErrInvalidPassword) {
		t.Fatalf("Hash(oversized) = %v, want ErrInvalidPassword", err)
	}
}

func TestVerifyMalformedHashes(t *testing.T) {
	hasher := testHasher(t)

	// A valid hash to borrow the salt/key encoding from.
	valid, err := hasher.Hash("some-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	fields := strings.Split(valid, "$")

	cases := map[string]string{
		"empty":          "",
		"plain text":     "not-a-hash",
		"missing fields": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA",
		"wrong scheme":   "$argon2i$v=19$m=8192,t=1,p=1$" + fields[4] + "$" + fields[5],
		"wrong version":  "$argon2id$v=16$m=8192,t=1,p=1$" + fields[4] + "$" + fields[5],
		"bad salt":       "$argon2id$v=19$m=8192,t=1,p=1$!!!!$" + fields[5],
		"short salt":     "$argon2id$v=19$m=8192,t=1,p=1$YQ$" + fields[5],
		"bad key":        "$argon2id$v=19$m=8192,t=1,p=1$" + fields[4] + "$!!!!",
		"short key":      "$argon2id$v=19$m=8192,t=1,p=1$" + fields[4] + "$YQ",
		"wild memory":    "$argon2id$v=19$m=99999999,t=1,p=1$" + fields[4] + "$" + fields[5],
		"zero passes":    "$argon2id$v=19$m=8192,t=0,p=1$" + fields[4] + "$" + fields[5],
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			err := hasher.Verify("some-password", encoded)
			if !errors.Is(err, passwd.ErrInvalidHash) {
				t.Fatalf("Verify(%q) = %v, want ErrInvalidHash", encoded, err)
			}
		})
	}
}

func TestVerifyRejectsOversizedPassword(t *testing.T) {
	hasher := testHasher(t)

	hash, err := hasher.Hash("short")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	err = hasher.Verify(strings.Repeat("a", passwd.MaxPasswordLen+1), hash)
	if !errors.Is(err, passwd.ErrMismatch) {
		t.Fatalf("Verify(oversized) = %v, want ErrMismatch", err)
	}
}

func TestNewHasherRejectsBadParams(t *testing.T) {
	cases := map[string]passwd.Params{
		"memory too small": {Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		"no passes":        {Memory: 8 * 1024, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		"no lanes":         {Memory: 8 * 1024, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		"short salt":       {Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32},
		"short key":        {Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := passwd.NewHasher(params); err == nil {
				t.Fatalf("NewHasher(%+v) accepted invalid parameters", params)
			}
		})
	}
}

func TestDefaultParamsAreUsable(t *testing.T) {
	hasher := passwd.NewDefaultHasher()
	if _, err := hasher.Hash("a-password"); err != nil {
		t.Fatalf("Hash with default params: %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := make(map[string]struct{}, 200)

	for i := 0; i < 200; i++ {
		password, err := passwd.GeneratePassword(passwd.BootstrapPasswordLen)
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		if len(password) != passwd.BootstrapPasswordLen {
			t.Fatalf("password %q has length %d, want %d", password, len(password), passwd.BootstrapPasswordLen)
		}

		var lower, upper, digit bool
		for _, r := range password {
			switch {
			case r >= 'a' && r <= 'z':
				lower = true
			case r >= 'A' && r <= 'Z':
				upper = true
			case r >= '0' && r <= '9':
				digit = true
			default:
				t.Fatalf("password %q contains unsupported character %q", password, r)
			}
		}
		if !lower || !upper || !digit {
			t.Fatalf("password %q does not mix lower case, upper case and digits", password)
		}

		if _, duplicate := seen[password]; duplicate {
			t.Fatalf("GeneratePassword repeated %q within 200 draws", password)
		}
		seen[password] = struct{}{}
	}
}

func TestGeneratePasswordRejectsShortLength(t *testing.T) {
	if _, err := passwd.GeneratePassword(3); err == nil {
		t.Fatal("GeneratePassword(3) succeeded, want an error")
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{
		"admin",
		"a",
		"user.name",
		"user_name",
		"user-name",
		"User123",
		strings.Repeat("a", passwd.MaxUsernameLen),
	}
	for _, username := range valid {
		if err := passwd.ValidateUsername(username); err != nil {
			t.Errorf("ValidateUsername(%q) = %v, want nil", username, err)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", passwd.MaxUsernameLen+1),
		"名字", // usernames are ASCII only
		"with space",
		"tab\there",
		"slash/name",
		"at@sign",
	}
	for _, username := range invalid {
		if err := passwd.ValidateUsername(username); !errors.Is(err, passwd.ErrInvalidUsername) {
			t.Errorf("ValidateUsername(%q) = %v, want ErrInvalidUsername", username, err)
		}
	}
}
