package otp

import (
	"strings"
	"testing"
	"time"
)

var rfcKey = []byte("12345678901234567890")

func TestHOTPVectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := HOTP(rfcKey, uint64(i), 6); got != w {
			t.Errorf("counter %d: got %s want %s", i, got, w)
		}
	}
}

func TestTOTPVectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		if got := TOTPAt(rfcKey, time.Unix(c.unix, 0), 8); got != c.want {
			t.Errorf("t=%d: got %s want %s", c.unix, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b32.DecodeString(secret)
	now := time.Unix(1_700_000_000, 0)
	step := now.Unix() / Period
	code := func(s int64) string { return HOTP(key, uint64(s), Digits) }

	got, ok := Validate(secret, code(step), now, 0)
	if !ok || got != step {
		t.Fatalf("current step: ok=%v got=%d want=%d", ok, got, step)
	}

	if _, ok := Validate(secret, code(step), now, step); ok {
		t.Fatal("replay was accepted")
	}

	if _, ok := Validate(secret, code(step-1), now, 0); !ok {
		t.Error("step-1 rejected")
	}
	if _, ok := Validate(secret, code(step+1), now, 0); !ok {
		t.Error("step+1 rejected")
	}
	if _, ok := Validate(secret, code(step-2), now, 0); ok {
		t.Error("step-2 accepted")
	}
	if _, ok := Validate(secret, code(step+2), now, 0); ok {
		t.Error("step+2 accepted")
	}

	for _, bad := range []string{"", "abc", "000000x", "12345"} {
		if _, ok := Validate(secret, bad, now, 0); ok && bad != code(step) {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, ok := Validate("not base32 !!", "123456", now, 0); ok {
		t.Error("accepted invalid secret")
	}
}

func TestURI(t *testing.T) {
	u := URI("CLI Login", "arnav", "JBSWY3DPEHPK3PXP")
	for _, part := range []string{
		"otpauth://totp/CLI%20Login:arnav?",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=CLI+Login",
		"digits=6", "period=30",
	} {
		if !strings.Contains(u, part) {
			t.Errorf("uri %q missing %q", u, part)
		}
	}
}
