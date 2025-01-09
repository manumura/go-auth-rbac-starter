package config

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	HTTPServerAddress              string `mapstructure:"HTTP_SERVER_ADDRESS" validate:"required"`
	GRPCServerAddress              string `mapstructure:"GRPC_SERVER_ADDRESS" validate:"required"`
	ClientAppUrl                   string `mapstructure:"CLIENT_APP_URL" validate:"required"`
	AccessTokenExpiresInAsSeconds  int    `mapstructure:"ACCESS_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	RefreshTokenExpiresInAsSeconds int    `mapstructure:"REFRESH_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	IdTokenExpiresInAsSeconds      int    `mapstructure:"ID_TOKEN_EXPIRES_IN_AS_SECONDS" validate:"required"`
	JwtSecret                      string `mapstructure:"JWT_SECRET" validate:"required"`
	GoogleClientId                 string `mapstructure:"GOOGLE_CLIENT_ID" validate:"required"`
	RecaptchaSecretKey             string `mapstructure:"RECAPTCHA_SECRET_KEY" validate:"required"`
	SmtpHost                       string `mapstructure:"SMTP_HOST" validate:"required"`
	SmtpPort                       int    `mapstructure:"SMTP_PORT" validate:"required"`
	SmtpUser                       string `mapstructure:"SMTP_USER" validate:"required"`
	SmtpPassword                   string `mapstructure:"SMTP_PASSWORD" validate:"required"`
	SmtpSecure                     bool   `mapstructure:"SMTP_SECURE" validate:"required"`
	SmtpFrom                       string `mapstructure:"ROOT_ACCOUNT_EMAIL" validate:"required"`
	DatabaseUrl                    string `mapstructure:"DATABASE_URL" validate:"required"`
	MaxOpenConnections             int    `mapstructure:"DATABASE_MAX_OPEN_CONNECTIONS" validate:"required"`
	MaxIdleConnections             int    `mapstructure:"DATABASE_MAX_IDLE_CONNECTIONS" validate:"required"`
	ConnectionMaxLifetime          int    `mapstructure:"DATABASE_CONNECTION_MAX_LIFETIME_IN_SECONDS" validate:"required"`
	ConnectionMaxIdleTime          int    `mapstructure:"DATABASE_CONNECTION_MAX_IDLE_TIME_IN_SECONDS" validate:"required"`
	TursoDatabaseUrl               string `mapstructure:"TURSO_DATABASE_URL" validate:"required"`
	TursoAuthToken                 string `mapstructure:"TURSO_AUTH_TOKEN" validate:"required"`
	AwsRegion                      string `mapstructure:"AWS_REGION" validate:"required"`
	AwsAccessKeyId                 string `mapstructure:"AWS_ACCESS_KEY_ID" validate:"required"`
	AwsSecretAccessKey             string `mapstructure:"AWS_SECRET_ACCESS_KEY" validate:"required"`
	AwsS3Bucket                    string `mapstructure:"AWS_S3_BUCKET" validate:"required"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(file string) (config Config, err error) {
	viper.SetConfigFile(file)
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	// This is needed to bind env variables to viper keys, as AutomaticEnv() is not working with Unmarshal.
	// https://github.com/spf13/viper/issues/188
	// NOTE: env keys should be defined in config file beforehand
	for _, key := range viper.AllKeys() {
		// envKey := strings.ToUpper(key)
		e := viper.BindEnv(key)
		if e != nil {
			log.Warn().Err(e).Msgf("cannot bind env key: %s", key)
		}
	}

	err = viper.Unmarshal(&config)
	return
}
