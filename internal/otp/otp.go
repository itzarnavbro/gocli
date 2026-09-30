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
	Period = 30
	skew   = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

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

func TOTPAt(key []byte, t time.Time, digits int) string {
	return HOTP(key, uint64(t.Unix()/Period), digits)
}

func GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// TOTP accepts a tiny skew, but same step kabhi replay nahi ho sakta.
func Validate(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	code = strings.TrimSpace(code)

	cur := now.Unix() / Period
	var matched int64
	found := false
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
