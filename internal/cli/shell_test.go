package cli

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/config"
	"github.com/itzarnavbro/gocli/internal/otp"
	"github.com/itzarnavbro/gocli/internal/store"
)

const pw = "correct horse"

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type step struct {
	line string
	fn   func() string
}

func lines(ss ...string) []step {
	out := make([]step, len(ss))
	for i, s := range ss {
		out[i] = step{line: s}
	}
	return out
}

type scriptIO struct {
	steps []step
	i     int
	out   bytes.Buffer
}

func (s *scriptIO) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *scriptIO) next(prompt string) (string, error) {
	s.out.WriteString(prompt)
	if s.i >= len(s.steps) {
		return "", io.EOF
	}
	st := s.steps[s.i]
	s.i++
	if st.fn != nil {
		return st.fn(), nil
	}
	return st.line, nil
}
func (s *scriptIO) ReadCommand(p string) (string, error)  { return s.next(p) }
func (s *scriptIO) ReadLine(p string) (string, error)     { return s.next(p) }
func (s *scriptIO) ReadPassword(p string) (string, error) { return s.next(p) }

type env struct {
	svc *auth.Service
	clk *fakeClock
	io  *scriptIO
}

func newEnv() *env {
	cfg := config.Config{
		Issuer:            "Test",
		SessionTTL:        10 * time.Minute,
		LockoutDuration:   15 * time.Minute,
		MaxFailedAttempts: 3,
		TOTPEncKey:        bytes.Repeat([]byte{7}, 32),
	}
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	return &env{svc: auth.New(store.NewMemory(), clk, cfg), clk: clk, io: &scriptIO{}}
}

func (e *env) run(t *testing.T, steps ...step) string {
	t.Helper()
	e.io.steps = steps
	if err := New(e.svc, e.clk, e.io).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e.io.out.String()
}

func mustContain(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n--- output ---\n%s", s, out)
		}
	}
}

func mustNotContain(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(out, s) {
			t.Errorf("output should not contain %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestHelpDependsOnLoginState(t *testing.T) {
	e := newEnv()
	out := e.run(t, lines("help", "register", "arnav", pw, pw, "login", "arnav", pw, "help", "exit")...)

	pre, post, ok := strings.Cut(out, "Logged in as")
	if !ok {
		t.Fatalf("never logged in:\n%s", out)
	}
	mustContain(t, pre, "register", "login", "exit")
	mustNotContain(t, pre, "whoami", "logout", "enable-2fa", "disable-2fa")
	mustContain(t, post, "whoami", "logout", "enable-2fa", "disable-2fa")
	mustNotContain(t, post, "register")
}

func TestRegisterLoginWhoamiLogout(t *testing.T) {
	e := newEnv()
	out := e.run(t, lines(
		"register", "arnav", pw, pw,
		"login", "arnav", pw,
		"whoami",
		"logout",
		"whoami",
		"nonsense",
		"exit",
	)...)

	mustContain(t, out,
		"created", "Logged in as arnav",
		"Username:", "Registered:", "2FA:", "disabled", "Session expires:", "Last login:", "first login",
		"Logged out", "You must log in first", "Unknown command", "Goodbye")
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv()
	out := e.run(t, lines(
		"register", "arnav", pw, "different password",
		"register", "ab", pw, pw,
		"register", "arnav", "short", "short",
		"exit",
	)...)
	mustContain(t, out, "Passwords do not match", "Username must be 3-32", "at least 8 characters")
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv()
	out := e.run(t, append(lines("register", "arnav", pw, pw, "login", "arnav", pw),
		step{fn: func() string { e.clk.Advance(11 * time.Minute); return "whoami" }},
		step{line: "exit"},
	)...)
	mustContain(t, out, "Session expired", "You must log in first")
}

func TestLockout(t *testing.T) {
	e := newEnv()
	out := e.run(t, lines(
		"register", "arnav", pw, pw,
		"login", "arnav", "wrong password one",
		"login", "arnav", "wrong password two",
		"login", "arnav", "wrong password three",
		"exit",
	)...)
	if n := strings.Count(out, "Invalid username or password"); n != 2 {
		t.Errorf("want 2 invalid-credentials errors, got %d\n%s", n, out)
	}
	mustContain(t, out, "Account locked until")
}

func Test2FAFlow(t *testing.T) {
	e := newEnv()

	code := step{fn: func() string {
		out := e.io.out.String()
		i := strings.LastIndex(out, "  Key:")
		line, _, _ := strings.Cut(out[i+len("  Key:"):], "\n")
		raw := strings.ReplaceAll(strings.TrimSpace(line), " ", "")
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(raw)
		if err != nil {
			t.Fatalf("bad key %q: %v", raw, err)
		}
		return otp.TOTPAt(key, e.clk.Now(), otp.Digits)
	}}

	var steps []step
	add := func(ss ...string) { steps = append(steps, lines(ss...)...) }

	add("register", "arnav", pw, pw, "login", "arnav", pw, "enable-2fa")
	steps = append(steps, code)
	add("whoami", "logout")
	steps = append(steps, step{fn: func() string { e.clk.Advance(30 * time.Second); return "login" }})
	add("arnav", pw)
	steps = append(steps, code)
	add("whoami", "exit")

	out := e.run(t, steps...)
	mustContain(t, out, "authentication enabled", "enabled")
	if n := strings.Count(out, "Logged in as"); n != 2 {
		t.Errorf("want 2 logins, got %d\n%s", n, out)
	}
}

func TestComplete(t *testing.T) {
	e := newEnv()
	s := New(e.svc, e.clk, e.io)

	cases := map[string][]string{
		"lo": {"login"},
		"e":  {"exit"},
		"":   {"exit", "help", "login", "register"},
		"zz": nil,
	}
	for prefix, want := range cases {
		if got := s.complete(prefix); !reflect.DeepEqual(got, want) {
			t.Errorf("complete(%q) = %v, want %v", prefix, got, want)
		}
	}
}

func TestCommonPrefix(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"enable-2fa", "exit"}, "e"},
		{[]string{"login"}, "login"},
		{[]string{"help", "login"}, ""},
		{nil, ""},
	} {
		if got := commonPrefix(c.in); got != c.want {
			t.Errorf("commonPrefix(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPlainIO(t *testing.T) {
	var out bytes.Buffer
	p := NewPlain(strings.NewReader("a\r\nb"), &out)
	for _, want := range []string{"a", "b"} {
		if got, err := p.ReadLine("> "); err != nil || got != want {
			t.Fatalf("got %q err=%v, want %q", got, err, want)
		}
	}
	if _, err := p.ReadLine("> "); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}
