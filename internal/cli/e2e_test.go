package cli

import (
	"context"
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/config"
	"github.com/itzarnavbro/gocli/internal/db"
	"github.com/itzarnavbro/gocli/internal/store"
)

func TestPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	cfg := config.Config{
		Issuer:            "Test",
		SessionTTL:        10 * time.Minute,
		LockoutDuration:   15 * time.Minute,
		MaxFailedAttempts: 3,
		TOTPEncKey:        bytes.Repeat([]byte{7}, 32),
	}

	// runOnce opens the DB, runs a scripted shell session, and closes everything,
	// like one start/stop of the container.
	runOnce := func(steps ...step) string {
		conn, err := db.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()

		sio := &scriptIO{steps: steps}
		svc := auth.New(store.NewSQLite(conn), clk, cfg)
		if err := New(svc, clk, sio).Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return sio.out.String()
	}

	runOnce(lines("register", "arnav", pw, pw, "login", "arnav", pw, "exit")...)

	clk.Advance(time.Hour)
	out := runOnce(lines("login", "arnav", pw, "exit")...)

	mustContain(t, out, "Logged in as arnav", "Last login:")
	mustNotContain(t, out, "first login") // last_login_at survived the restart
}