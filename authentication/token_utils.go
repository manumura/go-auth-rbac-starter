package authentication

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jaevor/go-nanoid"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/idtoken"
)

func generateToken(now time.Time, durationInSeconds int) (string, time.Time, error) {
	token, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate token")
		return "", time.Time{}, err
	}
	tokenAsString := token()
	tokenExpiresAt := now.Add(time.Duration(durationInSeconds) * time.Second)
	return tokenAsString, tokenExpiresAt, nil
}

func generateIdToken(now time.Time, durationInSeconds int, key []byte, user AuthenticatedUser) (string, time.Time, error) {
	idTokenExpiresAt := now.Add(time.Duration(durationInSeconds) * time.Second)
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat":  now.Unix(),
		"exp":  idTokenExpiresAt.Unix(),
		"iss":  "myapp",
		"user": user,
	})

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Error().Err(err).Msg("error parsing private key")
		return "", time.Time{}, err
	}

	idTokenAsString, err := idToken.SignedString(signKey)
	if err != nil {
		log.Error().Err(err).Msg("failed to create id token")
		return "", time.Time{}, err
	}
	return idTokenAsString, idTokenExpiresAt, nil
}

func verifyGoogleToken(token string, googleClientId string) (*idtoken.Payload, error) {
	tokenValidator, err := idtoken.NewValidator(context.Background())
	if err != nil {
		return &idtoken.Payload{}, err
	}

	payload, err := tokenValidator.Validate(context.Background(), token, googleClientId)
	if err != nil {
		return &idtoken.Payload{}, err
	}

	return payload, nil
}
