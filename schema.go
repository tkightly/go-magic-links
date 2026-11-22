package magiclink

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// migrations bring the module's tables up to date. Each runs once, in
// order, and is recorded in magiclink_schema, which belongs to this module
// (the app's own migrations and PRAGMA user_version are left alone). Never
// edit one that has shipped; append a new one.
var migrations = []string{
	// 1: links and sessions. IF NOT EXISTS because databases created before
	// magiclink_schema existed (v0.1.0) already have these tables.
	`
CREATE TABLE IF NOT EXISTS magiclink_links (
    token_hash  BLOB PRIMARY KEY,
    email       TEXT NOT NULL,
    state       TEXT,
    expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS magiclink_links_expires ON magiclink_links (expires_at);

CREATE TABLE IF NOT EXISTS magiclink_sessions (
    token_hash  BLOB PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    email       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS magiclink_sessions_expires ON magiclink_sessions (expires_at);
CREATE INDEX IF NOT EXISTS magiclink_sessions_user ON magiclink_sessions (user_id);
`,
	// 2: user IDs become opaque text (v0.2.0), so apps with UUID users can
	// use the module. Existing sessions are kept, their IDs as text.
	`
CREATE TABLE magiclink_sessions_v2 (
    token_hash  BLOB PRIMARY KEY,
    user_id     TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
) STRICT;
INSERT INTO magiclink_sessions_v2 (token_hash, user_id, email, created_at, expires_at)
    SELECT token_hash, CAST(user_id AS TEXT), email, created_at, expires_at FROM magiclink_sessions;
DROP TABLE magiclink_sessions;
ALTER TABLE magiclink_sessions_v2 RENAME TO magiclink_sessions;
CREATE INDEX magiclink_sessions_expires ON magiclink_sessions (expires_at);
CREATE INDEX magiclink_sessions_user ON magiclink_sessions (user_id);
`,
}

// migrate applies every migration not yet recorded, in one transaction, so
// a failure leaves the tables as they were.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS magiclink_schema (version INTEGER NOT NULL) STRICT`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRowContext(ctx, `SELECT version FROM magiclink_schema`).Scan(&version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `INSERT INTO magiclink_schema (version) VALUES (0)`); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this module supports (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE magiclink_schema SET version = ?`, len(migrations)); err != nil {
		return err
	}
	return tx.Commit()
}
