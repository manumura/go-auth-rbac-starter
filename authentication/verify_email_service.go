package authentication

import (
	"context"

	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

type VerifyEmailService interface {
	GetUserByVerifyEmailToken(ctx context.Context, token string) (user.UserEntity, error)
	UpdateIsEmailVerified(ctx context.Context, userID int64) error
}

type VerifyEmailServiceImpl struct {
	datastore   db.DataStore
	userService user.UserService
}

func NewVerifyEmailService(datastore db.DataStore, userService user.UserService) VerifyEmailService {
	return &VerifyEmailServiceImpl{
		datastore:   datastore,
		userService: userService,
	}
}

func (service *VerifyEmailServiceImpl) GetUserByVerifyEmailToken(ctx context.Context, token string) (user.UserEntity, error) {
	dbUser, err := service.datastore.GetUserByVerifyEmailToken(ctx, token)
	u := user.UserWithVerifyEmailTokenToUserEntity(dbUser.User, user.VerifyEmailTokenEntity{
		Token:     dbUser.VerifyEmailToken.Token,
		ExpiresAt: dbUser.VerifyEmailToken.ExpiresAt,
	})
	return u, err
}

func (service *VerifyEmailServiceImpl) UpdateIsEmailVerified(ctx context.Context, userID int64) error {
	err := service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		log.Info().Msg("updating user email verified")
		err = service.datastore.UpdateUserIsEmailVerified(ctx, db.UpdateUserIsEmailVerifiedParams{
			UserID:          userID,
			IsEmailVerified: 1,
		})
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		log.Info().Msg("deleting verify email token")
		err = service.datastore.DeleteVerifyEmailToken(ctx, userID)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		return nil
	})

	return err
}
