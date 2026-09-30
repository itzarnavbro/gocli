package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/itzarnavbro/gocli/internal/domain"
)

// SQLite implements domain.Store on top of *sql.DB.
type SQLite struct{ db *sql.DB }

func NewSQLite(db *sql.DB) *SQLite { return &SQLite{db: db} }

var _ domain.Store = (*SQLite)(nil)

// Times are stored as fixed-width UTC strings, so SQL comparisons like
// "expires_at <= ?" sort correctly as plain text.
const tsLayout = "2006-01-02 15:04:05.000000"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

// dbTime scans a nullable time column whether the driver hands back
// a string or an already-parsed time.Time.
type dbTime struct {
	T     time.Time
	Valid bool
}

func (d *dbTime) Scan(v any) error {
	switch x := v.(type) {
	case nil:
		d.T, d.Valid = time.Time{}, false
		return nil
	case time.Time:
		d.T, d.Valid = x.UTC(), true
		return nil
	case string:
		return d.parse(x)
	case []byte:
		return d.parse(string(x))
	default:
		return fmt.Errorf("unsupported time column type %T", v)
	}
}

func (d *dbTime) parse(s string) error {
	t, err := time.ParseInLocation(tsLayout, s, time.UTC)
	if err != nil {
		return fmt.Errorf("bad time %q: %w", s, err)
	}
	d.T, d.Valid = t, true
	return nil
}

func (d dbTime) ptr() *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.T
	return &t
}

const userCols = `id, username, password_hash, totp_secret_enc, totp_enabled,
	totp_last_step, failed_attempts, locked_until, created_at, last_login_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (*domain.User, error) {
	var (
		u                     domain.User
		secret                []byte
		enabled               int
		locked, created, last dbTime
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &secret, &enabled,
		&u.TOTPLastStep, &u.FailedAttempts, &locked, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(secret) > 0 {
		u.TOTPSecretEnc = secret
	}
	u.TOTPEnabled = enabled == 1
	u.LockedUntil = locked.ptr()
	u.CreatedAt = created.T
	u.LastLoginAt = last.ptr()
	return &u, nil
}

func (s *SQLite) CreateUser(ctx context.Context, u *domain.User) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		u.Username, u.PasswordHash, ts(u.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return domain.ErrUserExists
		}
		return err
	}
	u.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) UserByName(ctx context.Context, name string) (*domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

func (s *SQLite) UserByID(ctx context.Context, id int64) (*domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// RegisterFailure is one atomic UPDATE, so concurrent failures can't lose a count.
// When the count reaches max the account locks and the counter resets to 0,
// so a fresh lockout period always starts from a clean slate.
func (s *SQLite) RegisterFailure(ctx context.Context, id int64, max int, lockFor time.Duration, now time.Time) (int, *time.Time, error) {
	var (
		attempts int
		locked   dbTime
	)
	err := s.db.QueryRowContext(ctx, `
		UPDATE users SET
			failed_attempts = CASE WHEN failed_attempts + 1 >= ?1 THEN 0 ELSE failed_attempts + 1 END,
			locked_until    = CASE WHEN failed_attempts + 1 >= ?1 THEN ?2 ELSE locked_until END
		WHERE id = ?3
		RETURNING failed_attempts, locked_until`,
		max, ts(now.Add(lockFor)), id).Scan(&attempts, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, domain.ErrUserNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	// Only report a lock that is still in force.
	if locked.Valid && locked.T.After(now) {
		return attempts, locked.ptr(), nil
	}
	return attempts, nil, nil
}

func (s *SQLite) RecordLogin(ctx context.Context, id int64, now time.Time) error {
	return s.execOne(ctx,
		`UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`,
		ts(now), id)
}

// SetTOTP also resets totp_last_step, since a new secret starts a new step history.
func (s *SQLite) SetTOTP(ctx context.Context, id int64, secretEnc []byte, enabled bool) error {
	var secret any // stays nil (SQL NULL) when 2FA is being removed
	if len(secretEnc) > 0 {
		secret = secretEnc
	}
	en := 0
	if enabled {
		en = 1
	}
	return s.execOne(ctx,
		`UPDATE users SET totp_secret_enc = ?, totp_enabled = ?, totp_last_step = 0 WHERE id = ?`,
		secret, en, id)
}

func (s *SQLite) SetTOTPStep(ctx context.Context, id int64, step int64) error {
	return s.execOne(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ?`, step, id)
}

func (s *SQLite) UpdateHash(ctx context.Context, id int64, hash string) error {
	return s.execOne(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
}

func (s *SQLite) CreateSession(ctx context.Context, userID int64, tokenHash string, created, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		userID, tokenHash, ts(created), ts(expires))
	return err
}

func (s *SQLite) SessionByToken(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var (
		sess             domain.Session
		created, expires dbTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, created_at, expires_at FROM sessions WHERE token_hash = ?`,
		tokenHash).Scan(&sess.ID, &sess.UserID, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.ExpiresAt = created.T, expires.T
	return &sess, nil
}

func (s *SQLite) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *SQLite) DeleteExpired(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, ts(now))
	return err
}

// execOne runs an UPDATE that must hit exactly one user row.
func (s *SQLite) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}