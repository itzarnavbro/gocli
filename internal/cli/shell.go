package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/domain"
)

type Shell struct {
	svc  *auth.Service
	clk  domain.Clock
	tio  IO
	cmds []Command

	// session state (empty when logged out)
	token     string
	user      *domain.User
	sess      *domain.Session
	prevLogin *time.Time

	quit bool
}

func New(svc *auth.Service, clk domain.Clock, tio IO) *Shell {
	return &Shell{svc: svc, clk: clk, tio: tio, cmds: commands()}
}

// Run is the read-eval loop. Ctrl+D (or Ctrl+C) at the main prompt exits.
func (s *Shell) Run(ctx context.Context) error {
	if c, ok := s.tio.(completable); ok {
		c.SetCompleter(s.complete)
	}
	defer s.endSession(context.Background())

	s.printf("Go CLI Login. Type 'help' to see commands.\n")
	for !s.quit && ctx.Err() == nil {
		line, err := s.tio.ReadCommand(s.prompt())
		if errors.Is(err, io.EOF) {
			s.printf("\n")
			return nil
		}
		if err != nil {
			return err
		}
		s.dispatch(ctx, line)
	}
	return nil
}

func (s *Shell) dispatch(ctx context.Context, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	name, args := strings.ToLower(fields[0]), fields[1:]

	// Check the session before every command.
	if s.loggedIn() {
		if err := s.refresh(ctx); err != nil {
			s.report(err)
			return
		}
	}

	cmd, ok := s.find(name)
	switch {
	case !ok:
		s.errorf("Unknown command %q. Type 'help' to see available commands.", name)
	case !cmd.availableTo(s.loggedIn()):
		if cmd.Auth == LoggedIn {
			s.errorf("You must log in first. Use 'login'.")
		} else {
			s.errorf("You are already logged in. Use 'logout' first.")
		}
	default:
		if err := cmd.Run(ctx, s, args); err != nil {
			s.report(err)
		}
	}
}

// ---- session state ----

func (s *Shell) loggedIn() bool { return s.token != "" }

func (s *Shell) prompt() string {
	if s.loggedIn() && s.user != nil {
		return s.user.Username + "> "
	}
	return "auth> "
}

// refresh re-validates the session and reloads the user (so 2FA changes show up).
// An expired session is cleared and announced; the caller then continues logged out.
func (s *Shell) refresh(ctx context.Context) error {
	u, sess, err := s.svc.Validate(ctx, s.token)
	if err != nil {
		if errors.Is(err, domain.ErrSessionExpired) || errors.Is(err, domain.ErrSessionNotFound) {
			s.clearSession()
			s.errorf("Session expired. Please log in again.")
			return nil
		}
		return err
	}
	s.user, s.sess = u, sess
	return nil
}

func (s *Shell) clearSession() {
	s.token, s.user, s.sess, s.prevLogin = "", nil, nil, nil
}

// endSession logs out server-side (best effort) and clears local state.
func (s *Shell) endSession(ctx context.Context) {
	if s.token != "" {
		_ = s.svc.Logout(ctx, s.token)
	}
	s.clearSession()
}

// ---- output ----

func (s *Shell) printf(format string, a ...any)  { fmt.Fprintf(s.tio, format, a...) }
func (s *Shell) successf(format string, a ...any) { s.printf("✔ "+format+"\n", a...) }
func (s *Shell) errorf(format string, a ...any)   { s.printf("✘ "+format+"\n", a...) }

func (s *Shell) report(err error) {
	var locked domain.ErrLocked
	switch {
	case errors.Is(err, errCancelled):
		s.printf("Cancelled.\n")
	case errors.As(err, &locked):
		left := locked.Until.Sub(s.clk.Now()).Round(time.Second)
		s.errorf("%s (%s left).", sentence(err.Error()), left)
	case isUserError(err):
		s.errorf("%s.", sentence(err.Error()))
	default:
		slog.Error("command failed", "err", err)
		s.errorf("Something went wrong. Please try again.")
	}
}

func fmtTime(t time.Time) string { return t.Local().Format("02 Jan 2006 15:04:05 MST") }

// printUser shows the details required after login and by whoami.
func (s *Shell) printUser() {
	mfa := "disabled"
	if s.user.TOTPEnabled {
		mfa = "enabled"
	}
	last := "none (first login)"
	if s.prevLogin != nil {
		last = fmtTime(*s.prevLogin)
	}
	left := s.sess.ExpiresAt.Sub(s.clk.Now()).Round(time.Second)

	s.printf("  Username:         %s\n", s.user.Username)
	s.printf("  Registered:       %s\n", fmtTime(s.user.CreatedAt))
	s.printf("  2FA:              %s\n", mfa)
	s.printf("  Session expires:  %s (in %s)\n", fmtTime(s.sess.ExpiresAt), left)
	s.printf("  Last login:       %s\n", last)
}

// ---- input ----

// ask reads a visible answer; password prompts use askSecret.
func (s *Shell) ask(prompt string) (string, error) {
	v, err := s.tio.ReadLine(prompt)
	return strings.TrimSpace(v), cancelOnEOF(err)
}

func (s *Shell) askSecret(prompt string) (string, error) {
	v, err := s.tio.ReadPassword(prompt) // not trimmed: passwords may contain spaces
	return v, cancelOnEOF(err)
}

// Ctrl+D / Ctrl+C inside a prompt cancels the command instead of quitting.
func cancelOnEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return errCancelled
	}
	return err
}

func (s *Shell) usernameArg(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	return s.ask("Username: ")
}