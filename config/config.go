package config

import (
	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	appConfig
	envCongig
}

type envCongig struct {
	Environment        string `env:"ENV" validate:"required"`
	JwtSecret          string `env:"JWT_SECRET" validate:"required"`
	RecaptchaSecretKey string `env:"RECAPTCHA_SECRET_KEY" validate:"required"`
	SmtpUser           string `env:"SMTP_USER" validate:"required"`
	SmtpPassword       string `env:"SMTP_PASSWORD" validate:"required"`
	TursoAuthToken     string `env:"TURSO_AUTH_TOKEN" validate:"required"`
	AwsRegion          string `env:"AWS_REGION" validate:"required"`
	AwsAccessKeyId     string `env:"AWS_ACCESS_KEY_ID" validate:"required"`
	AwsSecretAccessKey string `env:"AWS_SECRET_ACCESS_KEY" validate:"required"`
}

type appConfig struct {
	HTTPServerAddress              string `mapstructure:"HTTP_SERVER_ADDRESS" validate:"required"`
	GRPCServerAddress              string `mapstructure:"GRPC_SERVER_ADDRESS" validate:"required"`
	ClientAppUrl                   string `mapstructure:"CLIENT_APP_URL" validate:"required"`
	AccessTokenExpiresInAsSeconds  int    `mapstructure:"ACCESS_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	RefreshTokenExpiresInAsSeconds int    `mapstructure:"REFRESH_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	IdTokenExpiresInAsSeconds      int    `mapstructure:"ID_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	GoogleClientId                 string `mapstructure:"GOOGLE_CLIENT_ID" validate:"required"`
	SmtpHost                       string `mapstructure:"SMTP_HOST" validate:"required"`
	SmtpPort                       int    `mapstructure:"SMTP_PORT" validate:"required"`
	SmtpSecure                     bool   `mapstructure:"SMTP_SECURE" validate:"required"`
	SmtpFrom                       string `mapstructure:"ROOT_ACCOUNT_EMAIL" validate:"required"`
	DatabaseUrl                    string `mapstructure:"DATABASE_URL" validate:"required"`
	MaxOpenConnections             int    `mapstructure:"DATABASE_MAX_OPEN_CONNECTIONS" validate:"required"`
	MaxIdleConnections             int    `mapstructure:"DATABASE_MAX_IDLE_CONNECTIONS" validate:"required"`
	ConnectionMaxLifetime          int    `mapstructure:"DATABASE_CONNECTION_MAX_LIFETIME_IN_SECONDS" validate:"required"`
	ConnectionMaxIdleTime          int    `mapstructure:"DATABASE_CONNECTION_MAX_IDLE_TIME_IN_SECONDS" validate:"required"`
	TursoDatabaseUrl               string `mapstructure:"TURSO_DATABASE_URL" validate:"required"`
	AwsS3Bucket                    string `mapstructure:"AWS_S3_BUCKET" validate:"required"`
}

func LoadConfig(file string, validate *validator.Validate) (Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("error loading .env file")
		return Config{}, err
	}

	var envConfig envCongig
	err = env.Parse(&envConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Error reading the environment variables")
		return Config{}, err
	}

	// Logger configuration
	ConfigureLogger(envConfig.Environment)

	viper.SetConfigFile(file)
	err = viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var appConfig appConfig
	err = viper.Unmarshal(&appConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("config validation failed")
		return Config{}, err
	}

	config := Config{
		appConfig: appConfig,
		envCongig: envConfig,
	}

	err = validate.Struct(config)
	if err != nil {
		log.Fatal().Err(err).Msg("config validation failed")
		return Config{}, err
	}

	return config, nil
}
