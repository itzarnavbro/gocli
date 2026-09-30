package cli

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/itzarnavbro/gocli/internal/auth"
	"github.com/itzarnavbro/gocli/internal/domain"
	"github.com/itzarnavbro/gocli/internal/password"
)

var (
	errCancelled        = errors.New("cancelled")
	errPasswordMismatch = errors.New("passwords do not match")
)

var userErrors = []error{
	domain.ErrInvalidCredentials, domain.ErrUserExists, domain.ErrInvalidCode,
	domain.ErrNo2FA, domain.ErrAlready2FA,
	auth.ErrInvalidUsername, password.ErrTooShort, password.ErrTooLong,
	errPasswordMismatch,
}

func isUserError(err error) bool {
	for _, e := range userErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func sentence(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}
