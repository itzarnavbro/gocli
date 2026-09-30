package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Digits = 6
	Period = 30 // seconds
	skew   = 1  // accept +-1 step for clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// HOTP implements RFC 4226 (HMAC-SHA1, dynamic truncation).
func HOTP(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPAt implements RFC 6238: HOTP with counter = unix time / period.
func TOTPAt(key []byte, t time.Time, digits int) string {
	return HOTP(key, uint64(t.Unix()/Period), digits)
}

// GenerateSecret returns a random 160-bit secret as unpadded base32
// (the format authenticator apps expect).
func GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// Validate checks code against steps now-1..now+1.
// Steps <= lastStep are rejected so a code can't be used twice.
// It returns the matched step, which the caller must persist.
func Validate(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	code = strings.TrimSpace(code)

	cur := now.Unix() / Period
	var matched int64
	found := false
	// No early return: every candidate step is compared.
	for s := cur - skew; s <= cur+skew; s++ {
		if s <= lastStep || s < 0 {
			continue
		}
		want := HOTP(key, uint64(s), Digits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched, found = s, true
		}
	}
	return matched, found
}

// URI builds the otpauth:// URL used for QR codes / manual entry.
func URI(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}