package config

import "github.com/spf13/viper"

type Config struct {
	Environment                    string `mapstructure:"ENVIRONMENT"`
	HTTPServerAddress              string `mapstructure:"HTTP_SERVER_ADDRESS"`
	GRPCServerAddress              string `mapstructure:"GRPC_SERVER_ADDRESS"`
	ClientAppUrl                   string `mapstructure:"CLIENT_APP_URL"`
	AccessTokenExpiresInAsSeconds  int    `mapstructure:"ACCESS_TOKEN_EXPIRES_IN_AS_SECONDS"`
	RefreshTokenExpiresInAsSeconds int    `mapstructure:"REFRESH_TOKEN_EXPIRES_IN_AS_SECONDS"`
	IdTokenExpiresInAsSeconds      int    `mapstructure:"ID_TOKEN_EXPIRES_IN_AS_SECONDS"`
	JwtSecret                      string `mapstructure:"JWT_SECRET"`
	GoogleClientId                 string `mapstructure:"GOOGLE_CLIENT_ID"`
	RecaptchaSecretKey             string `mapstructure:"RECAPTCHA_SECRET_KEY"`
	SmtpHost                       string `mapstructure:"SMTP_HOST"`
	SmtpPort                       int    `mapstructure:"SMTP_PORT"`
	SmtpUser                       string `mapstructure:"SMTP_USER"`
	SmtpPassword                   string `mapstructure:"SMTP_PASSWORD"`
	SmtpSecure                     bool   `mapstructure:"SMTP_SECURE"`
	SmtpFrom                       string `mapstructure:"ROOT_ACCOUNT_EMAIL"`
	DatabaseUrl                    string `mapstructure:"DATABASE_URL"`
	MaxOpenConnections             int    `mapstructure:"DATABASE_MAX_OPEN_CONNECTIONS"`
	MaxIdleConnections             int    `mapstructure:"DATABASE_MAX_IDLE_CONNECTIONS"`
	ConnectionMaxLifetime          int    `mapstructure:"DATABASE_CONNECTION_MAX_LIFETIME_IN_SECONDS"`
	ConnectionMaxIdleTime          int    `mapstructure:"DATABASE_CONNECTION_MAX_IDLE_TIME_IN_SECONDS"`
	TursoDatabaseUrl               string `mapstructure:"TURSO_DATABASE_URL"`
	TursoAuthToken                 string `mapstructure:"TURSO_AUTH_TOKEN"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(file string) (config Config, err error) {
	viper.SetConfigFile(file)
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
