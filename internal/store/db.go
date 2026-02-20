// Package store provides SQLite-backed event storage with dedup/cooldown.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/setevik/logtriage/internal/event"
	_ "github.com/mattn/go-sqlite3"
)

// DB wraps an SQLite connection for event storage.
type DB struct {
	db *sql.DB
}

// Open opens or creates an SQLite database at the given path.
func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Single writer connection to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}

// Insert stores a new event in the database.
func (d *DB) Insert(ev *event.Event) error {
	rawJSON, err := json.Marshal(ev.RawFields)
	if err != nil {
		rawJSON = []byte("{}")
	}

	_, err = d.db.Exec(`
		INSERT INTO events (id, instance_id, timestamp, tier, severity, summary, process, pid, unit, detail, raw_json, notified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID,
		ev.InstanceID,
		ev.Timestamp.UTC().Format(time.RFC3339Nano),
		string(ev.Tier),
		string(ev.Severity),
		ev.Summary,
		ev.Process,
		ev.PID,
		ev.Unit,
		ev.Detail,
		string(rawJSON),
		false,
	)
	if err != nil {
		return fmt.Errorf("inserting event: %w", err)
	}
	return nil
}

// MarkNotified marks an event as having been sent to ntfy.
func (d *DB) MarkNotified(id string) error {
	_, err := d.db.Exec(`UPDATE events SET notified = TRUE WHERE id = ?`, id)
	return err
}

// QueryFilter controls which events are returned by Query.
type QueryFilter struct {
	Since      time.Time
	Until      time.Time
	Tier       string
	InstanceID string
	Limit      int
}

// Query returns events matching the filter, ordered by timestamp descending.
func (d *DB) Query(f QueryFilter) ([]*event.Event, error) {
	query := `SELECT id, instance_id, timestamp, tier, severity, summary, process, pid, unit, detail, raw_json
		FROM events WHERE 1=1`
	var args []interface{}

	if !f.Since.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if f.Tier != "" {
		query += " AND tier = ?"
		args = append(args, f.Tier)
	}
	if f.InstanceID != "" {
		query += " AND instance_id = ?"
		args = append(args, f.InstanceID)
	}

	query += " ORDER BY timestamp DESC"

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var events []*event.Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// Purge deletes events older than the given retention duration.
func (d *DB) Purge(retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).UTC().Format(time.RFC3339Nano)
	result, err := d.db.Exec(`DELETE FROM events WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging old events: %w", err)
	}
	return result.RowsAffected()
}

func scanEvent(rows *sql.Rows) (*event.Event, error) {
	var ev event.Event
	var tsStr, rawJSON string
	var process, unit, detail sql.NullString

	err := rows.Scan(
		&ev.ID,
		&ev.InstanceID,
		&tsStr,
		&ev.Tier,
		&ev.Severity,
		&ev.Summary,
		&process,
		&ev.PID,
		&unit,
		&detail,
		&rawJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning event row: %w", err)
	}

	ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
	ev.Process = process.String
	ev.Unit = unit.String
	ev.Detail = detail.String
	ev.RawFields = make(map[string]string)
	if rawJSON != "" {
		_ = json.Unmarshal([]byte(rawJSON), &ev.RawFields)
	}

	return &ev, nil
}

func migrate(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id          TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL,
			timestamp   TEXT NOT NULL,
			tier        TEXT NOT NULL,
			severity    TEXT NOT NULL,
			summary     TEXT NOT NULL,
			process     TEXT,
			pid         INTEGER,
			unit        TEXT,
			detail      TEXT,
			raw_json    TEXT,
			notified    BOOLEAN DEFAULT FALSE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_instance_ts ON events(instance_id, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_tier ON events(tier, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(instance_id, tier, process, unit)`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	slog.Debug("database schema up to date")
	return nil
}
