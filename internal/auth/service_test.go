package auth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/itzarnavbro/gocli/internal/config"
	"github.com/itzarnavbro/gocli/internal/domain"
	"github.com/itzarnavbro/gocli/internal/otp"
	"github.com/itzarnavbro/gocli/internal/password"
	"github.com/itzarnavbro/gocli/internal/store"
)

var bg = context.Background()

const goodPW = "correct horse"

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Service, *fakeClock, *store.Memory) {
	t.Helper()
	cfg := config.Config{
		Issuer:            "Test",
		SessionTTL:        10 * time.Minute,
		LockoutDuration:   15 * time.Minute,
		MaxFailedAttempts: 3,
		TOTPEncKey:        bytes.Repeat([]byte{7}, 32),
	}
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	st := store.NewMemory()
	return New(st, clk, cfg), clk, st
}

func register(t *testing.T, svc *Service, name string) {
	t.Helper()
	if err := svc.Register(bg, name, goodPW); err != nil {
		t.Fatal(err)
	}
}

func fixedCode(c string) CodeFunc { return func() (string, error) { return c, nil } }

func codeNow(t *testing.T, secret string, clk *fakeClock) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return otp.TOTPAt(key, clk.Now(), otp.Digits)
}

func enable2FA(t *testing.T, svc *Service, clk *fakeClock, st *store.Memory, name string) string {
	t.Helper()
	user, err := st.UserByName(bg, name)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := svc.BeginEnable2FA(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmEnable2FA(bg, user.ID, enr.Secret, codeNow(t, enr.Secret, clk)); err != nil {
		t.Fatal(err)
	}
	return enr.Secret
}

func TestRegister(t *testing.T) {
	svc, _, _ := setup(t)

	if err := svc.Register(bg, "ab", goodPW); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("short username: %v", err)
	}
	if err := svc.Register(bg, "has space", goodPW); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("space in username: %v", err)
	}
	if err := svc.Register(bg, "arnav", "short"); !errors.Is(err, password.ErrTooShort) {
		t.Errorf("short password: %v", err)
	}

	register(t, svc, "Arnav")
	if err := svc.Register(bg, "ARNAV", goodPW); !errors.Is(err, domain.ErrUserExists) {
		t.Errorf("duplicate: %v", err)
	}
}

func TestLoginAndSession(t *testing.T) {
	svc, clk, _ := setup(t)
	register(t, svc, "arnav")

	token, err := svc.Login(bg, "ARNAV", goodPW, nil)
	if err != nil {
		t.Fatal(err)
	}
	user, sess, err := svc.Validate(bg, token)
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "arnav" || user.LastLoginAt == nil {
		t.Fatalf("user: %+v", user)
	}
	if !sess.ExpiresAt.Equal(clk.Now().Add(10 * time.Minute)) {
		t.Fatalf("expiry: %v", sess.ExpiresAt)
	}

	if err := svc.Logout(bg, token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Validate(bg, token); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("after logout: %v", err)
	}
}

func TestSameErrorForUnknownUserAndBadPassword(t *testing.T) {
	svc, _, _ := setup(t)
	register(t, svc, "arnav")

	_, e1 := svc.Login(bg, "nobody", goodPW, nil)
	_, e2 := svc.Login(bg, "arnav", "wrong password", nil)
	if !errors.Is(e1, domain.ErrInvalidCredentials) || !errors.Is(e2, domain.ErrInvalidCredentials) {
		t.Fatalf("got %v / %v", e1, e2)
	}
}

func TestLockout(t *testing.T) {
	svc, clk, _ := setup(t)
	register(t, svc, "arnav")

	for i := 0; i < 2; i++ {
		if _, err := svc.Login(bg, "arnav", "wrong password", nil); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}

	var locked domain.ErrLocked
	_, err := svc.Login(bg, "arnav", "wrong password", nil)
	if !errors.As(err, &locked) || !locked.Until.Equal(clk.Now().Add(15*time.Minute)) {
		t.Fatalf("3rd failure should lock: %v", err)
	}

	if _, err := svc.Login(bg, "arnav", goodPW, nil); !errors.As(err, &locked) {
		t.Fatalf("login during lock: %v", err)
	}

	clk.Advance(15*time.Minute + time.Second)
	if _, err := svc.Login(bg, "arnav", goodPW, nil); err != nil {
		t.Fatalf("after lock expired: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	svc, clk, _ := setup(t)
	register(t, svc, "arnav")
	token, err := svc.Login(bg, "arnav", goodPW, nil)
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(9 * time.Minute)
	if _, _, err := svc.Validate(bg, token); err != nil {
		t.Fatalf("still valid at 9m: %v", err)
	}

	clk.Advance(time.Minute)
	if _, _, err := svc.Validate(bg, token); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("at TTL: %v", err)
	}
	if _, _, err := svc.Validate(bg, token); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("expired session should be deleted: %v", err)
	}
}

func Test2FALogin(t *testing.T) {
	svc, clk, st := setup(t)
	register(t, svc, "arnav")
	secret := enable2FA(t, svc, clk, st, "arnav")

	if _, err := svc.Login(bg, "arnav", goodPW, nil); err == nil {
		t.Fatal("expected error when code prompt is missing")
	}

	if _, err := svc.Login(bg, "arnav", goodPW, fixedCode("abcdef")); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}

	if _, err := svc.Login(bg, "arnav", goodPW, fixedCode(codeNow(t, secret, clk))); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("confirmation code replay: %v", err)
	}

	clk.Advance(otp.Period * time.Second)
	code := codeNow(t, secret, clk)
	if _, err := svc.Login(bg, "arnav", goodPW, fixedCode(code)); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	if _, err := svc.Login(bg, "arnav", goodPW, fixedCode(code)); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("login code replay: %v", err)
	}
}

func TestDisable2FA(t *testing.T) {
	svc, clk, st := setup(t)
	register(t, svc, "arnav")
	secret := enable2FA(t, svc, clk, st, "arnav")
	user, _ := st.UserByName(bg, "arnav")

	clk.Advance(otp.Period * time.Second)
	code := codeNow(t, secret, clk)

	if err := svc.Disable2FA(bg, user.ID, "wrong password", code); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := svc.Disable2FA(bg, user.ID, goodPW, "abcdef"); !errors.Is(err, domain.ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := svc.Disable2FA(bg, user.ID, goodPW, code); err != nil {
		t.Fatalf("disable: %v", err)
	}

	if _, err := svc.Login(bg, "arnav", goodPW, nil); err != nil {
		t.Fatalf("login without 2FA: %v", err)
	}
	if err := svc.Disable2FA(bg, user.ID, goodPW, code); !errors.Is(err, domain.ErrNo2FA) {
		t.Fatalf("disable twice: %v", err)
	}
}

func TestSecretEncryptedAtRest(t *testing.T) {
	svc, clk, st := setup(t)
	register(t, svc, "arnav")
	secret := enable2FA(t, svc, clk, st, "arnav")

	u, _ := st.UserByName(bg, "arnav")
	if !u.TOTPEnabled || bytes.Contains(u.TOTPSecretEnc, []byte(secret)) {
		t.Fatal("secret stored in plaintext or 2FA not enabled")
	}
	got, err := open(svc.cfg.TOTPEncKey, u.TOTPSecretEnc, userAAD(u.ID))
	if err != nil || string(got) != secret {
		t.Fatalf("round trip: %q %v", got, err)
	}
}

func TestCrypt(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	ct, err := seal(key, []byte("secret"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := open(key, ct, []byte("a")); err != nil || string(pt) != "secret" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	if _, err := open(key, ct, []byte("b")); err == nil {
		t.Error("wrong AAD accepted")
	}
	if _, err := open(key, []byte{1, 2}, []byte("a")); err == nil {
		t.Error("short ciphertext accepted")
	}
	ct[len(ct)-1] ^= 1
	if _, err := open(key, ct, []byte("a")); err == nil {
		t.Error("tampered ciphertext accepted")
	}
}

func TestAuthenticateReportsPreviousLogin(t *testing.T) {
	svc, clk, _ := setup(t)
	register(t, svc, "arnav")

	first, err := svc.Authenticate(bg, "arnav", goodPW, nil)
	if err != nil || first.PreviousLogin != nil {
		t.Fatalf("first login: %+v err=%v", first, err)
	}
	t0 := clk.Now()

	clk.Advance(time.Hour)
	second, err := svc.Authenticate(bg, "arnav", goodPW, nil)
	if err != nil || second.PreviousLogin == nil || !second.PreviousLogin.Equal(t0) {
		t.Fatalf("second login: %+v err=%v", second, err)
	}
}

func TestLoginRehashesWeakHash(t *testing.T) {
	svc, clk, st := setup(t)

	salt := bytes.Repeat([]byte{1}, 16)
	key := argon2.IDKey([]byte(goodPW), salt, 1, 8*1024, 1, 32)
	b := base64.RawStdEncoding
	weak := fmt.Sprintf("$argon2id$v=19$m=8192,t=1,p=1$%s$%s", b.EncodeToString(salt), b.EncodeToString(key))

	if err := st.CreateUser(bg, &domain.User{Username: "legacy", PasswordHash: weak, CreatedAt: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(bg, "legacy", goodPW, nil); err != nil {
		t.Fatal(err)
	}

	u, _ := st.UserByName(bg, "legacy")
	if u.PasswordHash == weak || !strings.HasPrefix(u.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash was not upgraded: %s", u.PasswordHash)
	}
	if _, err := svc.Login(bg, "legacy", goodPW, nil); err != nil {
		t.Fatalf("login after rehash: %v", err)
	}
}
