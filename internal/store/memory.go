package store

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/itzarnavbro/gocli/internal/domain"
)

// Memory is an in-memory domain.Store for tests.
type Memory struct {
	mu       sync.Mutex
	nextID   int64
	users    map[int64]*domain.User
	sessions map[string]*domain.Session // key: token hash
}

func NewMemory() *Memory {
	return &Memory{
		nextID:   1,
		users:    map[int64]*domain.User{},
		sessions: map[string]*domain.Session{},
	}
}

var _ domain.Store = (*Memory)(nil)

// cp returns a copy so callers can't mutate stored state by accident.
func cp(u *domain.User) *domain.User {
	c := *u
	c.TOTPSecretEnc = append([]byte(nil), u.TOTPSecretEnc...)
	if len(c.TOTPSecretEnc) == 0 {
		c.TOTPSecretEnc = nil
	}
	if u.LockedUntil != nil {
		t := *u.LockedUntil
		c.LockedUntil = &t
	}
	if u.LastLoginAt != nil {
		t := *u.LastLoginAt
		c.LastLoginAt = &t
	}
	return &c
}

func (m *Memory) byName(name string) *domain.User {
	for _, u := range m.users {
		if strings.EqualFold(u.Username, name) { // matches COLLATE NOCASE
			return u
		}
	}
	return nil
}

func (m *Memory) CreateUser(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byName(u.Username) != nil {
		return domain.ErrUserExists
	}
	u.ID = m.nextID
	m.nextID++
	m.users[u.ID] = cp(u)
	return nil
}

func (m *Memory) UserByName(_ context.Context, name string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byName(name)
	if u == nil {
		return nil, domain.ErrUserNotFound
	}
	return cp(u), nil
}

func (m *Memory) UserByID(_ context.Context, id int64) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return cp(u), nil
}

func (m *Memory) RegisterFailure(_ context.Context, id int64, max int, lockFor time.Duration, now time.Time) (int, *time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return 0, nil, domain.ErrUserNotFound
	}
	u.FailedAttempts++
	if u.FailedAttempts >= max {
		u.FailedAttempts = 0
		until := now.Add(lockFor).UTC()
		u.LockedUntil = &until
	}
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		t := *u.LockedUntil
		return u.FailedAttempts, &t, nil
	}
	return u.FailedAttempts, nil, nil
}

func (m *Memory) RecordLogin(_ context.Context, id int64, now time.Time) error {
	return m.update(id, func(u *domain.User) {
		u.FailedAttempts, u.LockedUntil = 0, nil
		t := now.UTC()
		u.LastLoginAt = &t
	})
}

func (m *Memory) SetTOTP(_ context.Context, id int64, secretEnc []byte, enabled bool) error {
	return m.update(id, func(u *domain.User) {
		u.TOTPSecretEnc = append([]byte(nil), secretEnc...)
		if len(u.TOTPSecretEnc) == 0 {
			u.TOTPSecretEnc = nil
		}
		u.TOTPEnabled = enabled
		u.TOTPLastStep = 0
	})
}

func (m *Memory) SetTOTPStep(_ context.Context, id int64, step int64) error {
	return m.update(id, func(u *domain.User) { u.TOTPLastStep = step })
}

func (m *Memory) UpdateHash(_ context.Context, id int64, hash string) error {
	return m.update(id, func(u *domain.User) { u.PasswordHash = hash })
}

func (m *Memory) update(id int64, fn func(*domain.User)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	fn(u)
	return nil
}

func (m *Memory) CreateSession(_ context.Context, userID int64, tokenHash string, created, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[tokenHash] = &domain.Session{
		ID: int64(len(m.sessions) + 1), UserID: userID,
		CreatedAt: created.UTC(), ExpiresAt: expires.UTC(),
	}
	return nil
}

func (m *Memory) SessionByToken(_ context.Context, tokenHash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}
	c := *s
	return &c, nil
}

func (m *Memory) DeleteSession(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

func (m *Memory) DeleteExpired(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, k)
		}
	}
	return nil
}