package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/itzarnavbro/gocli/internal/config"
	"github.com/itzarnavbro/gocli/internal/domain"
	"github.com/itzarnavbro/gocli/internal/otp"
	"github.com/itzarnavbro/gocli/internal/password"
)

var ErrInvalidUsername = errors.New("username must be 3-32 characters: letters, digits or underscore")

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

type CodeFunc func() (string, error)

type Enrollment struct {
	Secret string
	URI    string
}

type Service struct {
	store domain.Store
	clock domain.Clock
	cfg   config.Config
}

func New(st domain.Store, clk domain.Clock, cfg config.Config) *Service {
	return &Service{store: st, clock: clk, cfg: cfg}
}

func normalize(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (s *Service) Register(ctx context.Context, username, pw string) error {
	username = normalize(username)
	if !usernameRe.MatchString(username) {
		return ErrInvalidUsername
	}
	if err := password.Validate(pw); err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	return s.store.CreateUser(ctx, &domain.User{
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    s.clock.Now(),
	})
}

func (s *Service) Login(ctx context.Context, username, pw string, code CodeFunc) (string, error) {
	now := s.clock.Now()

	user, err := s.store.UserByName(ctx, normalize(username))
	if errors.Is(err, domain.ErrUserNotFound) {
		_, _, _ = password.Verify(pw, password.Dummy())
		return "", domain.ErrInvalidCredentials
	}
	if err != nil {
		return "", err
	}

	if err := checkLocked(user, now); err != nil {
		return "", err
	}

	ok, rehash, err := password.Verify(pw, user.PasswordHash)
	if err != nil {
		return "", fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return "", s.fail(ctx, user.ID, now, domain.ErrInvalidCredentials)
	}

	if user.TOTPEnabled {
		if err := s.checkLoginCode(ctx, user, now, code); err != nil {
			return "", err
		}
	}

	if rehash {
		if h, err := password.Hash(pw); err == nil {
			_ = s.store.UpdateHash(ctx, user.ID, h)
		}
	}

	if err := s.store.RecordLogin(ctx, user.ID, now); err != nil {
		return "", err
	}

	token, err := newToken()
	if err != nil {
		return "", err
	}
	if err := s.store.CreateSession(ctx, user.ID, hashToken(token), now, now.Add(s.cfg.SessionTTL)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) checkLoginCode(ctx context.Context, user *domain.User, now time.Time, code CodeFunc) error {
	if code == nil {
		return errors.New("2FA code required but no prompt available")
	}
	entered, err := code()
	if err != nil {
		return err
	}
	secret, err := s.openSecret(user)
	if err != nil {
		return err
	}
	step, ok := otp.Validate(secret, entered, now, user.TOTPLastStep)
	if !ok {
		return s.fail(ctx, user.ID, now, domain.ErrInvalidCode)
	}
	return s.store.SetTOTPStep(ctx, user.ID, step)
}

// session token check: expired/missing means login again.
func (s *Service) Validate(ctx context.Context, token string) (*domain.User, *domain.Session, error) {
	now := s.clock.Now()
	h := hashToken(token)

	sess, err := s.store.SessionByToken(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	if !sess.ExpiresAt.After(now) {
		_ = s.store.DeleteSession(ctx, h)
		return nil, nil, domain.ErrSessionExpired
	}
	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	return user, sess, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, hashToken(token))
}

func (s *Service) BeginEnable2FA(user *domain.User) (Enrollment, error) {
	if user.TOTPEnabled {
		return Enrollment{}, domain.ErrAlready2FA
	}
	secret, err := otp.GenerateSecret()
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Secret: secret, URI: otp.URI(s.cfg.Issuer, user.Username, secret)}, nil
}

func (s *Service) ConfirmEnable2FA(ctx context.Context, userID int64, secret, code string) error {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.TOTPEnabled {
		return domain.ErrAlready2FA
	}
	step, ok := otp.Validate(secret, code, s.clock.Now(), 0)
	if !ok {
		return domain.ErrInvalidCode
	}
	enc, err := seal(s.cfg.TOTPEncKey, []byte(secret), userAAD(user.ID))
	if err != nil {
		return err
	}
	if err := s.store.SetTOTP(ctx, user.ID, enc, true); err != nil {
		return err
	}
	return s.store.SetTOTPStep(ctx, user.ID, step)
}

func (s *Service) Disable2FA(ctx context.Context, userID int64, pw, code string) error {
	now := s.clock.Now()
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return domain.ErrNo2FA
	}
	if err := checkLocked(user, now); err != nil {
		return err
	}
	ok, _, err := password.Verify(pw, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return s.fail(ctx, user.ID, now, domain.ErrInvalidCredentials)
	}
	secret, err := s.openSecret(user)
	if err != nil {
		return err
	}
	if _, ok := otp.Validate(secret, code, now, user.TOTPLastStep); !ok {
		return s.fail(ctx, user.ID, now, domain.ErrInvalidCode)
	}
	return s.store.SetTOTP(ctx, user.ID, nil, false)
}

func (s *Service) fail(ctx context.Context, id int64, now time.Time, bad error) error {
	_, until, err := s.store.RegisterFailure(ctx, id, s.cfg.MaxFailedAttempts, s.cfg.LockoutDuration, now)
	if err != nil {
		return err
	}
	if until != nil {
		return domain.ErrLocked{Until: *until}
	}
	return bad
}

func checkLocked(u *domain.User, now time.Time) error {
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		return domain.ErrLocked{Until: *u.LockedUntil}
	}
	return nil
}

func (s *Service) openSecret(u *domain.User) (string, error) {
	pt, err := open(s.cfg.TOTPEncKey, u.TOTPSecretEnc, userAAD(u.ID))
	if err != nil {
		return "", fmt.Errorf("decrypt 2FA secret: %w", err)
	}
	return string(pt), nil
}

// session token hash hi DB me save hota hai, isliye leaked DB se usable token nahi milta.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

type LoginResult struct {
	Token         string
	PreviousLogin *time.Time
}

func (s *Service) Authenticate(ctx context.Context, username, pw string, code CodeFunc) (LoginResult, error) {
	var prev *time.Time
	if u, err := s.store.UserByName(ctx, normalize(username)); err == nil {
		prev = u.LastLoginAt
	}
	token, err := s.Login(ctx, username, pw, code)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token, PreviousLogin: prev}, nil
}
