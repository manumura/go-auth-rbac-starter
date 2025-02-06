package config

import (
	"io"
	"os"
	"path"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

func ConfigureLogger(env string) {
	var writers []io.Writer

	writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr})
	if env == "dev" {
		f, err := newRollingFile()
		if err == nil {
			writers = append(writers, f)
		}
	}
	mw := io.MultiWriter(writers...)

	// zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = zerolog.New(mw).With().Timestamp().Logger()
}

func newRollingFile() (io.Writer, error) {
	if err := os.MkdirAll("logs", 0744); err != nil {
		log.Error().Err(err).Str("path", "logs").Msg("can't create logs directory")
		return nil, err
	}

	return &lumberjack.Logger{
		Filename:   path.Join("logs", "application.log"),
		MaxBackups: 10,  // files
		MaxSize:    10,  // megabytes
		MaxAge:     365, // days
	}, nil
}
