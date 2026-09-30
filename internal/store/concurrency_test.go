package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/itzarnavbro/gocli/internal/db"
	"github.com/itzarnavbro/gocli/internal/domain"
)

// 50 simultaneous failures must all be counted (no lost updates).
func TestRegisterFailureIsAtomic(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	s := NewSQLite(d)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	u := &domain.User{Username: "arnav", PasswordHash: "h", CreatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.RegisterFailure(ctx, u.ID, 1000, time.Minute, now) // max high enough to never lock
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, _ := s.UserByID(ctx, u.ID)
	if got.FailedAttempts != n {
		t.Fatalf("lost updates: want %d, got %d", n, got.FailedAttempts)
	}
}
