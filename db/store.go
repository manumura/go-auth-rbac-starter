package db

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/rs/zerolog/log"
)

type DataStore interface {
	Querier
	Connect() error
	Close() error
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

func (d *Database) Connect() error {
	log.Info().Msgf("connecting to database at: %s", d.config.DatabaseUrl)

	// Note : https://github.com/ncruces/go-sqlite-bench
	// Thanks to https://www.golang.dk/articles/go-and-sqlite-in-the-cloud
	// - Set WAL mode (not strictly necessary each time because it's persisted in the database, but good for first run)
	// - Set busy timeout, so concurrent writers wait on each other instead of erroring immediately
	// - Enable foreign key checks
	db, err := sql.Open("sqlite3", d.config.DatabaseUrl+"?_journal=WAL&_timeout=5000&_fk=true")
	if err != nil {
		return err
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
	r.Scan(&version)
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