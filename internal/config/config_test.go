package config

import (
	"strings"
	"testing"
	"time"
)

var goodKey = strings.Repeat("ef", 32)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"DB_PATH", "TOTP_ISSUER", "SESSION_TTL", "LOCKOUT_DURATION", "MAX_FAILED_ATTEMPTS"} {
		t.Setenv(k, "") // empty counts as unset, so the defaults apply
	}
	t.Setenv("TOTP_ENC_KEY", goodKey)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL != 15*time.Minute || c.MaxFailedAttempts != 5 {
		t.Fatalf("bad defaults = %+v", c)
	}
}

func TestLoadRejectsBad(t *testing.T) {
	cases := map[string]map[string]string{
		"short key":    {"TOTP_ENC_KEY": "abcd"},
		"non-hex key":  {"TOTP_ENC_KEY": strings.Repeat("zz", 32)},
		"bad ttl":      {"TOTP_ENC_KEY": goodKey, "SESSION_TTL": "soon"},
		"zero attempt": {"TOTP_ENC_KEY": goodKey, "MAX_FAILED_ATTEMPTS": "0"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
