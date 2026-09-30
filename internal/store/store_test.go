package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/itzarnavbro/gocli/internal/db"
	"github.com/itzarnavbro/gocli/internal/domain"
)

func TestMemory(t *testing.T) {
	contract(t, func(t *testing.T) domain.Store { return NewMemory() })
}

func TestSQLite(t *testing.T) {
	contract(t, func(t *testing.T) domain.Store {
		d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		return NewSQLite(d)
	})
}

// contract holds the behaviour every domain.Store must have.
func contract(t *testing.T, mk func(t *testing.T) domain.Store) {
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	newUser := func(t *testing.T, s domain.Store) *domain.User {
		u := &domain.User{Username: "arnav", PasswordHash: "h", CreatedAt: now}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	reload := func(t *testing.T, s domain.Store, id int64) *domain.User {
		u, err := s.UserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	t.Run("users", func(t *testing.T) {
		s := mk(t)
		u := newUser(t, s)
		if u.ID == 0 {
			t.Fatal("id not set")
		}

		dup := &domain.User{Username: "ARNAV", PasswordHash: "x", CreatedAt: now}
		if err := s.CreateUser(ctx, dup); !errors.Is(err, domain.ErrUserExists) {
			t.Fatalf("duplicate (case-insensitive): got %v", err)
		}

		got, err := s.UserByName(ctx, "Arnav")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != u.ID || !got.CreatedAt.Equal(now) || got.TOTPEnabled ||
			got.LockedUntil != nil || got.LastLoginAt != nil || got.TOTPSecretEnc != nil {
			t.Fatalf("unexpected user: %+v", got)
		}

		if _, err := s.UserByName(ctx, "nobody"); !errors.Is(err, domain.ErrUserNotFound) {
			t.Fatalf("missing by name: %v", err)
		}
		if _, err := s.UserByID(ctx, 9999); !errors.Is(err, domain.ErrUserNotFound) {
			t.Fatalf("missing by id: %v", err)
		}
	})

	t.Run("lockout", func(t *testing.T) {
		s := mk(t)
		u := newUser(t, s)

		for i := 1; i <= 2; i++ {
			n, lu, err := s.RegisterFailure(ctx, u.ID, 3, 15*time.Minute, now)
			if err != nil || n != i || lu != nil {
				t.Fatalf("failure %d: n=%d lu=%v err=%v", i, n, lu, err)
			}
		}
		n, lu, err := s.RegisterFailure(ctx, u.ID, 3, 15*time.Minute, now)
		if err != nil || n != 0 || lu == nil || !lu.Equal(now.Add(15*time.Minute)) {
			t.Fatalf("3rd failure should lock: n=%d lu=%v err=%v", n, lu, err)
		}
		if got := reload(t, s, u.ID); got.LockedUntil == nil || got.FailedAttempts != 0 {
			t.Fatalf("after lock: %+v", got)
		}

		later := now.Add(time.Hour)
		if err := s.RecordLogin(ctx, u.ID, later); err != nil {
			t.Fatal(err)
		}
		got := reload(t, s, u.ID)
		if got.FailedAttempts != 0 || got.LockedUntil != nil ||
			got.LastLoginAt == nil || !got.LastLoginAt.Equal(later) {
			t.Fatalf("after login: %+v", got)
		}

		if _, _, err := s.RegisterFailure(ctx, 9999, 3, time.Minute, now); !errors.Is(err, domain.ErrUserNotFound) {
			t.Fatalf("unknown id: %v", err)
		}
	})

	t.Run("totp and hash", func(t *testing.T) {
		s := mk(t)
		u := newUser(t, s)

		secret := []byte{1, 2, 3, 4}
		if err := s.SetTOTP(ctx, u.ID, secret, true); err != nil {
			t.Fatal(err)
		}
		got := reload(t, s, u.ID)
		if !got.TOTPEnabled || !bytes.Equal(got.TOTPSecretEnc, secret) {
			t.Fatalf("after enable: %+v", got)
		}

		if err := s.SetTOTPStep(ctx, u.ID, 55); err != nil {
			t.Fatal(err)
		}
		if got := reload(t, s, u.ID); got.TOTPLastStep != 55 {
			t.Fatalf("step: %d", got.TOTPLastStep)
		}

		if err := s.SetTOTP(ctx, u.ID, nil, false); err != nil {
			t.Fatal(err)
		}
		got = reload(t, s, u.ID)
		if got.TOTPEnabled || got.TOTPSecretEnc != nil || got.TOTPLastStep != 0 {
			t.Fatalf("after disable: %+v", got)
		}

		if err := s.UpdateHash(ctx, u.ID, "newhash"); err != nil {
			t.Fatal(err)
		}
		if got := reload(t, s, u.ID); got.PasswordHash != "newhash" {
			t.Fatalf("hash: %s", got.PasswordHash)
		}
	})

	t.Run("sessions", func(t *testing.T) {
		s := mk(t)
		u := newUser(t, s)

		if err := s.CreateSession(ctx, u.ID, "short", now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateSession(ctx, u.ID, "long", now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}

		got, err := s.SessionByToken(ctx, "short")
		if err != nil || got.UserID != u.ID || !got.ExpiresAt.Equal(now.Add(time.Minute)) {
			t.Fatalf("lookup: %+v err=%v", got, err)
		}
		if _, err := s.SessionByToken(ctx, "nope"); !errors.Is(err, domain.ErrSessionNotFound) {
			t.Fatalf("missing session: %v", err)
		}

		if err := s.DeleteExpired(ctx, now.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SessionByToken(ctx, "short"); !errors.Is(err, domain.ErrSessionNotFound) {
			t.Fatal("expired session survived DeleteExpired")
		}
		if _, err := s.SessionByToken(ctx, "long"); err != nil {
			t.Fatalf("live session was deleted: %v", err)
		}

		if err := s.DeleteSession(ctx, "long"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SessionByToken(ctx, "long"); !errors.Is(err, domain.ErrSessionNotFound) {
			t.Fatal("session survived DeleteSession")
		}
	})
}
