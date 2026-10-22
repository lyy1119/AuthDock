package passwd

import (
	"bytes"
	"errors"
	"testing"
)

// goldenHash was produced by the Argon2 reference implementation for the fixed
// salt "0123456789abcdef", password "correct horse battery staple" and the
// default cost parameters. It pins this package to the standard PHC encoding, so
// a regression in encode or decode cannot silently change the on-disk format.
const (
	goldenPassword = "correct horse battery staple"
	goldenSalt     = "0123456789abcdef"
	goldenHash     = "$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$UqcjN8FEhR9C3aVPAePbwhjlawq6mqKGGOFCbIG7i8U"
)

func TestGoldenVectorDecodes(t *testing.T) {
	params, salt, key, err := decode(goldenHash)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := DefaultParams()
	if params != want {
		t.Fatalf("params = %+v, want %+v", params, want)
	}
	if string(salt) != goldenSalt {
		t.Fatalf("salt = %q, want %q", salt, goldenSalt)
	}
	if len(key) != int(want.KeyLength) {
		t.Fatalf("key length = %d, want %d", len(key), want.KeyLength)
	}
	if got := encode(params, salt, key); got != goldenHash {
		t.Fatalf("encode(decode(golden)) =\n  %q\nwant\n  %q", got, goldenHash)
	}
}

func TestGoldenVectorVerifies(t *testing.T) {
	hasher := NewDefaultHasher()

	if err := hasher.Verify(goldenPassword, goldenHash); err != nil {
		t.Fatalf("Verify with the golden password: %v", err)
	}
	if err := hasher.Verify(goldenPassword+"!", goldenHash); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify with a wrong password = %v, want ErrMismatch", err)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	params := Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	salt := bytes.Repeat([]byte{0xab}, int(params.SaltLength))
	key := bytes.Repeat([]byte{0xcd}, int(params.KeyLength))

	encoded := encode(params, salt, key)
	gotParams, gotSalt, gotKey, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode(encode(...)): %v", err)
	}
	if gotParams != params {
		t.Fatalf("params = %+v, want %+v", gotParams, params)
	}
	if !bytes.Equal(gotSalt, salt) {
		t.Fatalf("salt = %x, want %x", gotSalt, salt)
	}
	if !bytes.Equal(gotKey, key) {
		t.Fatalf("key = %x, want %x", gotKey, key)
	}
	if again := encode(gotParams, gotSalt, gotKey); again != encoded {
		t.Fatalf("re-encoding changed the string:\n  %q\n  %q", encoded, again)
	}
}

func TestDecodeRejectsOutOfRangeCosts(t *testing.T) {
	cases := map[string]string{
		"memory too small": "$argon2id$v=19$m=1024,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$UqcjN8FEhR9C3aVPAePbwhjlawq6mqKGGOFCbIG7i8U",
		"memory too large": "$argon2id$v=19$m=99999999,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$UqcjN8FEhR9C3aVPAePbwhjlawq6mqKGGOFCbIG7i8U",
		"no passes":        "$argon2id$v=19$m=65536,t=0,p=2$MDEyMzQ1Njc4OWFiY2RlZg$UqcjN8FEhR9C3aVPAePbwhjlawq6mqKGGOFCbIG7i8U",
		"no lanes":         "$argon2id$v=19$m=65536,t=3,p=0$MDEyMzQ1Njc4OWFiY2RlZg$UqcjN8FEhR9C3aVPAePbwhjlawq6mqKGGOFCbIG7i8U",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decode(encoded); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("decode(%q) = %v, want ErrInvalidHash", encoded, err)
			}
		})
	}
}
