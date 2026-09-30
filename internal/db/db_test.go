package db

import (
	"path/filepath"
	"testing"
)

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	for i := 0; i < 2; i++ {
		d, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}

		var tables int
		if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('users','sessions')`).Scan(&tables); err != nil {
			t.Fatal(err)
		}
		if tables != 2 {
			t.Fatalf("run %d: want 2 tables, got %d", i, tables)
		}

		var applied int
		if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied != 1 {
			t.Fatalf("run %d: want 1 migration applied, got %d", i, applied)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
