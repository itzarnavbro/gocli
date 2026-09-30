package domain

import (
	"context"
	"errors"
	"time"
)

type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	TOTPSecretEnc  []byte
	TOTPEnabled    bool
	TOTPLastStep   int64
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	LastLoginAt    *time.Time
}

type Session struct {
	ID        int64
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

type Store interface {
	CreateUser(ctx context.Context, u *User) error
	UserByName(ctx context.Context, name string) (*User, error)
	UserByID(ctx context.Context, id int64) (*User, error)

	RegisterFailure(ctx context.Context, id int64, max int, lockFor time.Duration, now time.Time) (attempts int, lockedUntil *time.Time, err error)
	RecordLogin(ctx context.Context, id int64, now time.Time) error

	SetTOTP(ctx context.Context, id int64, secretEnc []byte, enabled bool) error
	SetTOTPStep(ctx context.Context, id int64, step int64) error
	UpdateHash(ctx context.Context, id int64, hash string) error

	CreateSession(ctx context.Context, userID int64, tokenHash string, created, expires time.Time) error
	SessionByToken(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteExpired(ctx context.Context, now time.Time) error
}

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserExists         = errors.New("username already taken")
	ErrUserNotFound       = errors.New("user not found")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidCode        = errors.New("invalid 2FA code")
	ErrNo2FA              = errors.New("2FA is not enabled")
	ErrAlready2FA         = errors.New("2FA is already enabled")
)

// account lockout ka status yahi return karta hai.
type ErrLocked struct{ Until time.Time }

func (e ErrLocked) Error() string {
	return "account locked until " + e.Until.Local().Format("15:04:05 02 Jan 2006")
}
