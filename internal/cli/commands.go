package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/domain"
)

func commands() []Command {
	return []Command{
		{"help", "show available commands", Any, cmdHelp},
		{"register", "create a new account", Anonymous, cmdRegister},
		{"login", "log in with username and password", Anonymous, cmdLogin},
		{"whoami", "show current user details", LoggedIn, cmdWhoami},
		{"enable-2fa", "turn on two-factor authentication", LoggedIn, cmdEnable2FA},
		{"disable-2fa", "turn off two-factor authentication", LoggedIn, cmdDisable2FA},
		{"logout", "end the current session", LoggedIn, cmdLogout},
		{"exit", "quit the program", Any, cmdExit},
	}
}

func cmdHelp(_ context.Context, s *Shell, _ []string) error {
	s.printf("Available commands:\n")
	for _, c := range s.Available() {
		s.printf("  %-12s %s\n", c.Name, c.Help)
	}
	return nil
}

func cmdRegister(ctx context.Context, s *Shell, args []string) error {
	s.printf("Username: 3-32 characters (a-z, 0-9, _). Password: at least 8 characters.\n")
	username, err := s.usernameArg(args)
	if err != nil {
		return err
	}
	pw, err := s.askSecret("Password: ")
	if err != nil {
		return err
	}
	confirm, err := s.askSecret("Confirm password: ")
	if err != nil {
		return err
	}
	if pw != confirm {
		return errPasswordMismatch
	}
	if err := s.svc.Register(ctx, username, pw); err != nil {
		return err
	}
	s.successf("Account %q created. You can now log in.", strings.ToLower(username))
	return nil
}

func cmdLogin(ctx context.Context, s *Shell, args []string) error {
	username, err := s.usernameArg(args)
	if err != nil {
		return err
	}
	pw, err := s.askSecret("Password: ")
	if err != nil {
		return err
	}

	res, err := s.svc.Authenticate(ctx, username, pw, func() (string, error) {
		return s.askSecret("2FA code: ")
	})
	if err != nil {
		return err
	}

	s.token, s.prevLogin = res.Token, res.PreviousLogin
	if err := s.refresh(ctx); err != nil {
		s.clearSession()
		return err
	}
	if !s.loggedIn() {
		return fmt.Errorf("session invalid right after login")
	}
	s.successf("Logged in as %s.", s.user.Username)
	s.printUser()
	return nil
}

func cmdWhoami(_ context.Context, s *Shell, _ []string) error {
	s.printUser()
	return nil
}

func cmdEnable2FA(ctx context.Context, s *Shell, _ []string) error {
	enr, err := s.svc.BeginEnable2FA(s.user)
	if err != nil {
		return err
	}

	s.printf("Add this account to your authenticator app\n")
	s.printf("(Google Authenticator: + > Enter a setup key, time-based):\n\n")
	s.printf("  Account:  %s\n", s.user.Username)
	s.printf("  Key:      %s\n\n", groups(enr.Secret, 4))
	s.printf("Or use this URI in an app that accepts otpauth links:\n  %s\n\n", enr.URI)

	const tries = 3
	for i := 1; i <= tries; i++ {
		code, err := s.askSecret("Enter the 6-digit code from the app: ")
		if err != nil {
			return err
		}
		err = s.svc.ConfirmEnable2FA(ctx, s.user.ID, enr.Secret, code)
		if errors.Is(err, domain.ErrInvalidCode) && i < tries {
			s.errorf("Incorrect code. Try again (%d left).", tries-i)
			continue
		}
		if err != nil {
			return err
		}
		if err := s.refresh(ctx); err != nil {
			return err
		}
		s.successf("Two-factor authentication enabled.")
		return nil
	}
	return nil
}

func cmdDisable2FA(ctx context.Context, s *Shell, _ []string) error {
	if !s.user.TOTPEnabled {
		return domain.ErrNo2FA
	}
	s.printf("Confirm your identity to disable two-factor authentication.\n")
	pw, err := s.askSecret("Password: ")
	if err != nil {
		return err
	}
	code, err := s.askSecret("2FA code: ")
	if err != nil {
		return err
	}

	err = s.svc.Disable2FA(ctx, s.user.ID, pw, code)
	var locked domain.ErrLocked
	if errors.As(err, &locked) {
		s.report(err)
		s.endSession(ctx)
		s.printf("You have been logged out.\n")
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.refresh(ctx); err != nil {
		return err
	}
	s.successf("Two-factor authentication disabled.")
	return nil
}

func cmdLogout(ctx context.Context, s *Shell, _ []string) error {
	s.endSession(ctx)
	s.successf("Logged out.")
	return nil
}

func cmdExit(_ context.Context, s *Shell, _ []string) error {
	s.quit = true
	s.printf("Goodbye.\n")
	return nil
}

func groups(s string, n int) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%n == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

var _ = auth.ErrInvalidUsername // keeps the import if you trim commands later
