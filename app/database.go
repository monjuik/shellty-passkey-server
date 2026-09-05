package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/monjuik/shellty-passkey-server/assets"
)

const schemaVersion = 1
const migrationLock int64 = 739245761834

// Migrate serializes startup migrations across nodes and validates file checksums.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return err
	}
	// A failed unlock must not return a session holding the lock to the pool.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), databaseTimeout)
		defer cancel()
		if _, e := conn.Exec(cleanup, "SELECT pg_advisory_unlock($1)", migrationLock); e != nil {
			_ = conn.Conn().Close(cleanup)
		}
	}()
	if _, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS migration (version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	entries, err := assets.Migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for i, entry := range entries {
		version := i + 1
		if !strings.HasPrefix(entry.Name(), fmt.Sprintf("%03d_", version)) {
			return fmt.Errorf("invalid migration sequence")
		}
		sql, err := assets.Migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(sql))
		var stored string
		err = conn.QueryRow(ctx, "SELECT checksum FROM migration WHERE version=$1", version).Scan(&stored)
		if err == nil {
			if checksum != stored {
				return fmt.Errorf("migration %d checksum mismatch", version)
			}
			continue
		}
		if err != pgx.ErrNoRows {
			return err
		}
		var latest int
		if err = conn.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM migration").Scan(&latest); err != nil {
			return err
		}
		if latest != version-1 {
			return fmt.Errorf("unsupported or noncontiguous schema")
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, string(sql))
		if err == nil {
			_, err = tx.Exec(ctx, "INSERT INTO migration(version,checksum) VALUES($1,$2)", version, checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return checkSchema(ctx, conn)
}
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) error { return checkSchema(ctx, pool) }

type schemaReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func checkSchema(ctx context.Context, pool schemaReader) error {
	var count, max int
	if err := pool.QueryRow(ctx, "SELECT count(*), COALESCE(max(version),0) FROM migration").Scan(&count, &max); err != nil {
		return err
	}
	if count != schemaVersion || max != schemaVersion {
		return fmt.Errorf("unsupported database schema")
	}
	return nil
}
