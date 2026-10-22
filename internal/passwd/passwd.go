// Package passwd implements the password primitives AuthDock needs: Argon2id
// hashing for storage, constant-time verification, and the random bootstrap
// password handed out with the default administrator account.
//
// The key derivation itself comes from golang.org/x/crypto/argon2, the Go
// project's implementation of Argon2. The PHC string around it
// ($argon2id$v=19$m=...,t=...,p=...$salt$key, the format of the Argon2 reference
// implementation) is small and stable enough to encode and parse here, which
// keeps the module dependency list down to the SQLite driver.
package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MaxUsernameLen is the maximum username length in runes. It mirrors the
	// users_username_len constraint in the database schema.
	MaxUsernameLen = 20

	// MinPasswordLen is the shortest password accepted when an account is
	// created or its password is reset from the admin area.
	MinPasswordLen = 8

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
type Params struct {
	Memory      uint32 // memory cost in KiB
	Iterations  uint32 // number of passes
	Parallelism uint8  // number of lanes
	SaltLength  uint32 // salt length in bytes
	KeyLength   uint32 // derived key length in bytes
}

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
func (p Params) validateCost() error {
	switch {
	case p.Memory < 8*1024 || p.Memory > maxArgonMemory:
		return fmt.Errorf("memory cost out of range: %d KiB", p.Memory)
	case p.Iterations < 1 || p.Iterations > 64:
		return fmt.Errorf("iteration count out of range: %d", p.Iterations)
	case p.Parallelism < 1 || p.Parallelism > 32:
		return fmt.Errorf("parallelism out of range: %d", p.Parallelism)
	}
	return nil
}

// validateParams checks a full parameter set used to derive new hashes.
func (p Params) validateParams() error {
	if err := p.validateCost(); err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	switch {
	case p.SaltLength < 8 || p.SaltLength > 64:
		return fmt.Errorf("passwd: salt length out of range: %d", p.SaltLength)
	case p.KeyLength < 16 || p.KeyLength > 64:
		return fmt.Errorf("passwd: key length out of range: %d", p.KeyLength)
	}
	return nil
}

// Hasher derives and verifies Argon2id password hashes.
type Hasher struct {
	params Params
}

// NewHasher returns a Hasher using the given cost parameters.
func NewHasher(params Params) (*Hasher, error) {
	if err := params.validateParams(); err != nil {
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

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwd: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return encode(h.params, salt, key), nil
}

// Verify reports whether password matches encoded. The cost parameters and salt
// are read back from encoded itself and the comparison is constant time.
func (h *Hasher) Verify(password, encoded string) error {
	if len(password) > MaxPasswordLen {
		return ErrMismatch
	}

	params, salt, key, err := decode(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return ErrMismatch
	}
	return nil
}

// encode renders the PHC string format of the Argon2 reference implementation.
func encode(params Params, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// decode parses a string produced by encode. The cost parameters, the salt and
// the key length are all validated here, before the caller feeds them into
// argon2.IDKey, because that call allocates Memory KiB.
func decode(encoded string) (Params, []byte, []byte, error) {
	var params Params

	// "", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<key>"
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return params, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params, nil, nil, fmt.Errorf("%w: malformed version field", ErrInvalidHash)
	}
	if version != argon2.Version {
		return params, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidHash, version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return params, nil, nil, fmt.Errorf("%w: malformed cost field", ErrInvalidHash)
	}
	if err := params.validateCost(); err != nil {
		return params, nil, nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return params, nil, nil, fmt.Errorf("%w: malformed salt", ErrInvalidHash)
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return params, nil, nil, fmt.Errorf("%w: malformed key", ErrInvalidHash)
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	return params, salt, key, nil
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

// ValidateNewPassword checks a password chosen by an administrator when creating
// an account or resetting its password.
func ValidateNewPassword(password string) error {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return fmt.Errorf("%w: length must be between %d and %d bytes",
			ErrInvalidPassword, MinPasswordLen, MaxPasswordLen)
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
