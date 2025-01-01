package authentication

import (
	"context"
	"time"

	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/rs/zerolog/log"
)

type AuthenticationService interface {
	CreateAuthentication(ctx context.Context, req AuthenticationRequest) (db.AuthenticationToken, error)
	GetByAccessToken(ctx context.Context, token string) (db.AuthenticationToken, error)
	GetByRefreshToken(ctx context.Context, token string) (db.AuthenticationToken, error)
	DeleteAuthenticationTokenByUserID(ctx context.Context, userID int64) error
}

type AuthenticationServiceImpl struct {
	datastore db.DataStore
}

func NewAuthenticationService(datastore db.DataStore) AuthenticationService {
	return &AuthenticationServiceImpl{
		datastore: datastore,
	}
}

func (service *AuthenticationServiceImpl) CreateAuthentication(ctx context.Context, req AuthenticationRequest) (db.AuthenticationToken, error) {
	var t db.AuthenticationToken

	err := service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		log.Info().Msg("deleting existing authentication token")
		err = q.DeleteAuthenticationToken(ctx, req.UserID)
		if err != nil {
			return err
		}

		log.Info().Msg("creating new authentication token")
		now := time.Now().UTC()
		r := db.CreateAuthenticationTokenParams{
			UserID:                req.UserID,
			AccessToken:           req.AccessToken,
			AccessTokenExpiresAt:  req.AccessTokenExpiresAt.Format(time.DateTime),
			RefreshToken:          req.RefreshToken,
			RefreshTokenExpiresAt: req.RefreshTokenExpiresAt.Format(time.DateTime),
			CreatedAt:             now.Format(time.DateTime),
		}

		t, err = q.CreateAuthenticationToken(ctx, r)
		if err != nil {
			return err
		}

		log.Info().Msg("new authentication token created")
		return nil
	})

	return t, err
}

func (service *AuthenticationServiceImpl) GetByAccessToken(ctx context.Context, token string) (db.AuthenticationToken, error) {
	t, err := service.datastore.GetAuthenticationTokenByAccessToken(ctx, token)
	return t, err
}

func (service *AuthenticationServiceImpl) GetByRefreshToken(ctx context.Context, token string) (db.AuthenticationToken, error) {
	t, err := service.datastore.GetAuthenticationTokenByRefreshToken(ctx, token)
	return t, err
}

func (service *AuthenticationServiceImpl) DeleteAuthenticationTokenByUserID(ctx context.Context, userID int64) error {
	err := service.datastore.DeleteAuthenticationToken(ctx, userID)
	return err
}
