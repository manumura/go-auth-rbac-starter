package authentication

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	RESET_PASSWORD_TOKEN_EXPIRY_DURATION_IN_HOURS = 24
)

type ResetPasswordService interface {
	GetUserByEmail(ctx context.Context, email string) (user.UserEntity, error)
	CreateResetPasswordToken(ctx context.Context, userID int64) (db.ResetPasswordToken, error)
	GetUserByResetPasswordToken(ctx context.Context, token string) (user.UserEntity, error)
	UpdatePassword(ctx context.Context, userID int64, password string) error
}

type ResetPasswordServiceImpl struct {
	datastore   db.DataStore
	userService user.UserService
}

func NewResetPasswordService(datastore db.DataStore, userService user.UserService) ResetPasswordService {
	return &ResetPasswordServiceImpl{
		datastore:   datastore,
		userService: userService,
	}
}

func (service *ResetPasswordServiceImpl) GetUserByEmail(ctx context.Context, email string) (user.UserEntity, error) {
	return service.userService.GetByEmail(ctx, email)
}

func (service *ResetPasswordServiceImpl) CreateResetPasswordToken(ctx context.Context, userID int64) (db.ResetPasswordToken, error) {
	var t db.ResetPasswordToken

	err := service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		log.Info().Msg("deleting existing token")
		err = q.DeleteVerifyEmailToken(ctx, userID)
		if err != nil {
			return err
		}

		log.Info().Msg("creating new token")
		now := time.Now().UTC()
		token := uuid.New().String()
		r := db.CreateResetPasswordTokenParams{
			UserID:    userID,
			Token:     token,
			ExpiresAt: now.Add(time.Hour * RESET_PASSWORD_TOKEN_EXPIRY_DURATION_IN_HOURS).Format(time.DateTime),
			CreatedAt: now.Format(time.DateTime),
		}

		t, err = q.CreateResetPasswordToken(ctx, r)
		if err != nil {
			return err
		}

		log.Info().Msg("new token created")
		return nil
	})

	return t, err
}

func (service *ResetPasswordServiceImpl) GetUserByResetPasswordToken(ctx context.Context, token string) (user.UserEntity, error) {
	dbUser, err := service.datastore.GetUserByResetPasswordToken(ctx, token)
	u := user.UserWithResetPasswordTokenToUserEntity(dbUser.User, user.ResetPasswordToken{
		Token:     dbUser.ResetPasswordToken.Token,
		ExpiresAt: dbUser.ResetPasswordToken.ExpiresAt,
	})
	return u, err
}

func (service *ResetPasswordServiceImpl) UpdatePassword(ctx context.Context, userID int64, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	err = service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		// var err error

		log.Info().Msg("update user password by userID")
		p := db.UpdateUserPasswordParams{
			Password: string(hashedPassword),
			UserID:   userID,
		}
		err = q.UpdateUserPassword(ctx, p)
		if err != nil {
			return err
		}

		log.Info().Msg("delete reset password token by userID")
		err = q.DeleteResetPasswordToken(ctx, userID)
		if err != nil {
			return err
		}

		log.Info().Msg("password updated")
		return nil
	})

	return err
}
