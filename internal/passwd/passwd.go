// Package passwd implements the password primitives AuthDock needs: Argon2id
// hashing for storage, constant-time verification, and the random bootstrap
// password handed out with the default administrator account.
//
// The hash encoding itself is delegated to github.com/alexedwards/argon2id, a
// small, audited wrapper around golang.org/x/crypto/argon2. This package only
// adds AuthDock's policy on top: a password length cap, cost parameter bounds
// (so a corrupted hash cannot make verification allocate unbounded memory) and
// the username rules.
package passwd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/alexedwards/argon2id"
)

const (
	// MaxUsernameLen is the maximum username length in runes. It mirrors the
	// users_username_len constraint in the database schema.
	MaxUsernameLen = 20

	// MaxPasswordLen bounds the password length accepted by Hash and Verify so
	// that a single request cannot force unbounded work.
	MaxPasswordLen = 1024

	// BootstrapPasswordLen is the length of the password generated for the
	// default administrator account on first start-up.
	BootstrapPasswordLen = 8

	// maxArgonMemory is a sanity bound applied when verifying a stored hash, so
	// a corrupted or hostile hash can never make Verify allocate unbounded RAM.
	maxArgonMemory = 1 << 20 // 1 GiB
)

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var (
	// ErrInvalidHash reports a stored hash that is not a usable Argon2id hash.
	ErrInvalidHash = errors.New("passwd: invalid hash encoding")
	// ErrMismatch reports a password that does not match the stored hash.
	ErrMismatch = errors.New("passwd: password mismatch")
	// ErrInvalidUsername reports a username that violates the naming rules.
	ErrInvalidUsername = errors.New("passwd: invalid username")
	// ErrInvalidPassword reports an empty or oversized password.
	ErrInvalidPassword = errors.New("passwd: invalid password")
)

// Params are the Argon2id cost parameters used to derive new hashes. They are
// stored inside every hash string, so verification keeps working after the
// defaults are tuned.
type Params = argon2id.Params

// DefaultParams returns the parameters new hashes are created with: 64 MiB of
// memory, 3 passes over 2 lanes. Login is an infrequent admin action, so the
// extra cost is affordable and raises the price of an offline attack.
func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// validateCost bounds the cost parameters that are read back from a stored hash.
func validateCost(params Params) error {
	switch {
	case params.Memory < 8*1024 || params.Memory > maxArgonMemory:
		return fmt.Errorf("memory cost out of range: %d KiB", params.Memory)
	case params.Iterations < 1 || params.Iterations > 64:
		return fmt.Errorf("iteration count out of range: %d", params.Iterations)
	case params.Parallelism < 1 || params.Parallelism > 32:
		return fmt.Errorf("parallelism out of range: %d", params.Parallelism)
	}
	return nil
}

// validateParams checks a full parameter set used to derive new hashes.
func validateParams(params Params) error {
	if err := validateCost(params); err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	switch {
	case params.SaltLength < 8 || params.SaltLength > 64:
		return fmt.Errorf("passwd: salt length out of range: %d", params.SaltLength)
	case params.KeyLength < 16 || params.KeyLength > 64:
		return fmt.Errorf("passwd: key length out of range: %d", params.KeyLength)
	}
	return nil
}

// Hasher derives and verifies Argon2id password hashes.
type Hasher struct {
	params Params
}

// NewHasher returns a Hasher using the given cost parameters.
func NewHasher(params Params) (*Hasher, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}
	return &Hasher{params: params}, nil
}

// NewDefaultHasher returns a Hasher using DefaultParams.
func NewDefaultHasher() *Hasher {
	hasher, err := NewHasher(DefaultParams())
	if err != nil {
		// DefaultParams is a compile-time constant validated by tests, so a
		// failure here means the source was edited incorrectly.
		panic(fmt.Sprintf("passwd: invalid default parameters: %v", err))
	}
	return hasher
}

// Hash derives a new Argon2id hash for password and returns it in the PHC
// string format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
//
// The salt is random for every call, so hashing the same password twice yields
// different strings.
func (h *Hasher) Hash(password string) (string, error) {
	if password == "" || len(password) > MaxPasswordLen {
		return "", ErrInvalidPassword
	}
	hash, err := argon2id.CreateHash(password, &h.params)
	if err != nil {
		return "", fmt.Errorf("passwd: hash password: %w", err)
	}
	return hash, nil
}

// Verify reports whether password matches encoded. The cost parameters and salt
// are read back from encoded itself and the comparison is constant time.
func (h *Hasher) Verify(password, encoded string) error {
	if len(password) > MaxPasswordLen {
		return ErrMismatch
	}

	// Validate the cost parameters before the library uses them: DecodeHash is
	// cheap, while the key derivation that follows allocates Memory KiB.
	params, salt, key, err := argon2id.DecodeHash(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	if err := validateCost(*params); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	if len(salt) < 8 || len(key) < 16 {
		return fmt.Errorf("%w: salt or key too short", ErrInvalidHash)
	}

	match, err := argon2id.ComparePasswordAndHash(password, encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	if !match {
		return ErrMismatch
	}
	return nil
}

// ValidateUsername enforces the username rules shared by the bootstrap account,
// the database schema and the login API: 1 to MaxUsernameLen runes taken from
// [A-Za-z0-9._-].
func ValidateUsername(username string) error {
	if n := utf8.RuneCountInString(username); n == 0 || n > MaxUsernameLen {
		return fmt.Errorf("%w: username must be 1-%d characters, got %d", ErrInvalidUsername, MaxUsernameLen, n)
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("%w: unsupported character %q", ErrInvalidUsername, r)
		}
	}
	return nil
}

// GeneratePassword returns a random password of n characters drawn from the
// alphanumeric alphabet. Every character class (lower case, upper case, digit)
// appears at least once. Bytes are drawn with rejection sampling, so the
// distribution stays uniform instead of picking up modulo bias.
func GeneratePassword(n int) (string, error) {
	if n < 4 {
		return "", fmt.Errorf("passwd: password length %d is too short", n)
	}

	// Reject bytes that would make the modulo mapping non-uniform.
	const acceptBelow = 256 - (256 % len(passwordAlphabet))

	buf := make([]byte, n)
	for attempt := 0; attempt < 1000; attempt++ {
		out := make([]byte, 0, n)
		for len(out) < n {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("passwd: read random bytes: %w", err)
			}
			for _, b := range buf {
				if int(b) >= acceptBelow {
					continue
				}
				out = append(out, passwordAlphabet[int(b)%len(passwordAlphabet)])
				if len(out) == n {
					break
				}
			}
		}
		candidate := string(out)
		if hasAllClasses(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("passwd: failed to generate a password with all character classes")
}

// hasAllClasses reports whether s contains a lower case letter, an upper case
// letter and a digit.
func hasAllClasses(s string) bool {
	var lower, upper, digit bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return lower && upper && digit
}
