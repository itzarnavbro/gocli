package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

type params struct {
	m       uint32
	t       uint32
	p       uint8
	saltLen uint32
	keyLen  uint32
}

var current = params{m: 64 * 1024, t: 3, p: 2, saltLen: 16, keyLen: 32}

var b64 = base64.RawStdEncoding

var (
	ErrTooShort    = errors.New("password must be at least 8 characters")
	ErrTooLong     = errors.New("password must be at most 128 bytes")
	errBadEncoding = errors.New("invalid password hash encoding")
)

func Validate(pw string) error {
	if utf8.RuneCountInString(pw) < 8 {
		return ErrTooShort
	}
	if len(pw) > 128 {
		return ErrTooLong
	}
	return nil
}

func Hash(pw string) (string, error) {
	salt := make([]byte, current.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, current.t, current.m, current.p, current.keyLen)
	return encode(current, salt, key), nil
}

func Verify(pw, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(pw), salt, p.t, p.m, p.p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, p.m < current.m || p.t < current.t || p.p < current.p, nil
}

var (
	dummyOnce sync.Once
	dummy     string
)

// known-user vs unknown-user timing match karne ke liye dummy hash use hota hai.
func Dummy() string {
	dummyOnce.Do(func() { dummy, _ = Hash("dummy-password-for-timing") })
	return dummy
}

func encode(p params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.m, p.t, p.p, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(enc string) (p params, salt, key []byte, err error) {
	parts := strings.Split(enc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, errBadEncoding
	}

	var v int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return p, nil, nil, errBadEncoding
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.m, &p.t, &p.p); err != nil {
		return p, nil, nil, errBadEncoding
	}
	if p.t < 1 || p.t > 10 || p.p < 1 || p.p > 16 || p.m < 8 || p.m > 256*1024 {
		return p, nil, nil, errBadEncoding
	}

	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) < 8 || len(salt) > 64 {
		return p, nil, nil, errBadEncoding
	}
	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, errBadEncoding
	}
	return p, salt, key, nil
}
