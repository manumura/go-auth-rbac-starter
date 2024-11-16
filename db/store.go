package db

import (
	"context"
	"database/sql"
	"embed"
	"strconv"
	"time"

	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog/log"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

const (
	maxConnectAttempts = 10
)

type DataStore interface {
	Querier
	Connect() error
	Close() error
	MigrateUp() error
	MigrateDown() error
	ExecTx(ctx context.Context, fn func(*Queries) error) error
}

type Database struct {
	config config.Config
	db     *sql.DB
	*Queries
}

// func NewDataStore(db *sql.DB) DataStore {
func NewDataStore(config config.Config) DataStore {
	return &Database{
		config: config,
		// DB: db,
		// Queries: New(DB),
	}
}

func (d *Database) ExecTx(ctx context.Context, fn func(*Queries) error) error {
	log.Info().Msg("beginning transaction")
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := d.Queries.WithTx(tx)

	err = fn(q)
	if err != nil {
		log.Error().Err(err).Msg("transaction failed: rolling back")
		// if rbErr := tx.Rollback(); rbErr != nil {
		// 	log.Error().Err(rbErr).Msg("cannot rollback transaction")
		// 	return fmt.Errorf("tx err: %v, rollback err: %v", err, rbErr)
		// }
		return err
	}

	log.Info().Msg("committing transaction")
	return tx.Commit()
}

// TODO turso https://github.com/hadyrashwan/golang-for-node-devs/blob/main/backend/api/dboperations/operations.go
func (d *Database) Connect() error {
	// log.Info().Msgf("connecting to database at: %s", d.config.TursoDatabaseUrl)
	// url := d.config.TursoDatabaseUrl + "?authToken=" + d.config.TursoAuthToken
	// db, err := sql.Open("libsql", url)

	// Note : https://github.com/ncruces/go-sqlite-bench
	// Thanks to https://www.golang.dk/articles/go-and-sqlite-in-the-cloud
	// - Set WAL mode (not strictly necessary each time because it's persisted in the database, but good for first run)
	// - Set busy timeout, so concurrent writers wait on each other instead of erroring immediately
	// - Enable foreign key checks

	log.Info().Msgf("connecting to database at: %s", d.config.DatabaseUrl)
	db, err := sql.Open("sqlite3", d.config.DatabaseUrl+"?_journal=WAL&_timeout=5000&_fk=true")
	if err != nil {
		return err
	}

	var dbError error
	for attempt := 1; attempt <= maxConnectAttempts; attempt++ {
		dbError = db.Ping()
		if dbError == nil {
			break
		}
		log.Info().Msgf("cannot connect to db (%d): %s\n", attempt, dbError)
		// sleep with exponential backoff
		time.Sleep(time.Duration(attempt*attempt) * time.Second)
	}
	if dbError != nil {
		return dbError
	}

	log.Info().Msgf("setting database connection pool options ("+
		"max open connections: %s, max idle connections: %s, connection max lifetime: %s, connection max idle time: %s)",
		strconv.Itoa(d.config.MaxOpenConnections),
		strconv.Itoa(d.config.MaxIdleConnections),
		strconv.Itoa(d.config.ConnectionMaxLifetime),
		strconv.Itoa(d.config.ConnectionMaxIdleTime))
	db.SetMaxOpenConns(d.config.MaxOpenConnections)
	db.SetMaxIdleConns(d.config.MaxIdleConnections)
	db.SetConnMaxLifetime(time.Duration(d.config.ConnectionMaxLifetime) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(d.config.ConnectionMaxIdleTime) * time.Second)

	// get SQLite version
	var version string
	r := db.QueryRow("select sqlite_version()")
	err = r.Scan(&version)
	if err != nil {
		log.Error().Err(err).Msg("cannot get SQLite version")
		return err
	}
	log.Info().Msgf("SQLite version is: %s", version)

	d.db = db
	d.Queries = New(db)
	return nil
}

func (d *Database) Close() error {
	log.Info().Msg("closing database connection")
	err := d.db.Close()
	if err != nil {
		log.Error().Err(err).Msg("cannot close database connection")
		return err
	}
	log.Info().Msg("database connection closed")
	return nil
}

//go:embed sql/migration/*.sql
var embedMigrations embed.FS

func (d *Database) MigrateUp() error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	if err := goose.Up(d.db, "sql/migration"); err != nil {
		return err
	}

	log.Info().Msg("db migrated up successfully")
	return nil
}

func (d *Database) MigrateDown() error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	if err := goose.Down(d.db, "sql/migration"); err != nil {
		return err
	}

	log.Info().Msg("db migrated down successfully")
	return nil
}
