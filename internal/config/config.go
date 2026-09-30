package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DBPath            string
	Issuer            string
	SessionTTL        time.Duration
	LockoutDuration   time.Duration
	MaxFailedAttempts int
	TOTPEncKey        []byte // 32 bytes, AES-256
}

// Load reads config from env vars and fails fast on bad values.
func Load() (Config, error) {
	var c Config
	var err error

	c.DBPath = getenv("DB_PATH", "/data/app.db")
	c.Issuer = getenv("TOTP_ISSUER", "CLI-Login")

	if c.SessionTTL, err = duration("SESSION_TTL", "15m"); err != nil {
		return c, err
	}
	if c.LockoutDuration, err = duration("LOCKOUT_DURATION", "15m"); err != nil {
		return c, err
	}
	if c.MaxFailedAttempts, err = integer("MAX_FAILED_ATTEMPTS", "5"); err != nil {
		return c, err
	}

	key, err := hex.DecodeString(os.Getenv("TOTP_ENC_KEY"))
	if err != nil || len(key) != 32 {
		return c, fmt.Errorf("TOTP_ENC_KEY must be 64 hex chars (32 bytes)")
	}
	c.TOTPEncKey = key

	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func duration(k, def string) (time.Duration, error) {
	d, err := time.ParseDuration(getenv(k, def))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration like 15m", k)
	}
	return d, nil
}

func integer(k, def string) (int, error) {
	n, err := strconv.Atoi(getenv(k, def))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", k)
	}
	return n, nil
}