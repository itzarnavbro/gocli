package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/cli"
	"github.com/itzarnavbro/gocli/internal/config"
	"github.com/itzarnavbro/gocli/internal/db"
	"github.com/itzarnavbro/gocli/internal/domain"
	"github.com/itzarnavbro/gocli/internal/store"
)

func main() { os.Exit(run()) }

func run() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "database error:", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	clk := domain.RealClock{}
	st := store.NewSQLite(conn)
	svc := auth.New(st, clk, cfg)

	go reap(ctx, st, clk, time.Minute)

	shell := cli.New(svc, clk, cli.NewIO())
	done := make(chan error, 1)
	go func() { done <- shell.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nshutting down")
	}
	return 0
}

// expired sessions cleanup startup + periodic sweep ke liye hai.
func reap(ctx context.Context, st domain.Store, clk domain.Clock, every time.Duration) {
	sweep := func() {
		if err := st.DeleteExpired(ctx, clk.Now()); err != nil && ctx.Err() == nil {
			slog.Warn("session cleanup failed", "err", err)
		}
	}
	sweep()

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
