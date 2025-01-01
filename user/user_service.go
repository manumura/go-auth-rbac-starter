package user

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	VERIFY_EMAIL_TOKEN_EXPIRY_DURATION_IN_HOURS = 24
)

type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (UserEntity, error)
	CreateOauth(ctx context.Context, req CreateOauthUserRequest) (UserEntity, error)
	GetAll(ctx context.Context) ([]UserEntity, error)
	GetByEmail(ctx context.Context, email string) (UserEntity, error)
	GetByID(ctx context.Context, id int64) (UserEntity, error)
	GetByUUID(ctx context.Context, uuid string) (UserEntity, error)
	GetByOauthProvider(ctx context.Context, provider oauthprovider.OauthProvider, externalUserID string) (UserEntity, error)
	CheckPassword(password string, hashedPassword string) error
	GetByVerifyEmailToken(ctx context.Context, token string) (UserEntity, error)
	UpdateIsEmailVerified(ctx context.Context, userID int64) error
}

type UserServiceImpl struct {
	datastore db.DataStore
}

func NewUserService(datastore db.DataStore) UserService {
	roleService := role.NewRoleService(datastore)
	roleService.InitRolesMaps(context.Background())

	oauthProviderService := oauthprovider.NewOauthProviderService(datastore)
	oauthProviderService.InitProvidersMaps(context.Background())

	return &UserServiceImpl{
		datastore: datastore,
	}
}

func (service *UserServiceImpl) Create(ctx context.Context, req CreateUserRequest) (UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		return UserEntity{}, err
	}

	var user UserEntity
	err = service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		log.Info().Msg("creating new user")
		p := db.CreateUserParams{
			Uuid:      uuid.New().String(),
			Name:      req.Name,
			IsActive:  1,
			RoleID:    role.RoleNameToID[req.Role.String()],
			CreatedAt: nowAsString,
			UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
		}

		u, err := q.CreateUser(ctx, p)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		log.Info().Msg("creating new user credentials")
		ucp := db.CreateUserCredentialsParams{
			UserID:          u.ID,
			Email:           req.Email,
			Password:        string(hashedPassword),
			IsEmailVerified: 0,
		}
		uc, err := q.CreateUserCredentials(ctx, ucp)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		log.Info().Msg("creating email verification token")
		token := uuid.New().String()
		expiresAt := now.Add(time.Hour * VERIFY_EMAIL_TOKEN_EXPIRY_DURATION_IN_HOURS).Format(time.DateTime)
		vetp := db.CreateVerifyEmailTokenParams{
			UserID:    u.ID,
			Token:     token,
			ExpiresAt: expiresAt,
			CreatedAt: nowAsString,
			UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
		}
		_, err = q.CreateVerifyEmailToken(ctx, vetp)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		user = UserCredentialsWithVerifyEmailTokenToUserEntity(u, uc, VerifyEmailToken{
			Token:     token,
			ExpiresAt: expiresAt,
		})
		log.Info().Msgf("new user created: %s", user.Uuid)
		return nil
	})

	return user, err
}

func (service *UserServiceImpl) CreateOauth(ctx context.Context, req CreateOauthUserRequest) (UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	var user UserEntity
	err := service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		log.Info().Msg("creating new user")
		p := db.CreateUserParams{
			Uuid:      uuid.New().String(),
			Name:      req.Name,
			IsActive:  1,
			RoleID:    role.RoleNameToID[req.Role.String()],
			CreatedAt: nowAsString,
			UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
		}

		u, err := q.CreateUser(ctx, p)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		log.Info().Msg("creating new oauth user")
		oup := db.CreateOauthUserParams{
			UserID:          u.ID,
			OauthProviderID: oauthprovider.OauthProviderNameToID[req.OauthProvider.String()],
			ExternalUserID:  req.ExternalUserID,
			Email:           req.Email,
		}

		ou, err := q.CreateOauthUser(ctx, oup)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		user = OauthUserToUserEntity(u, ou)
		log.Info().Msgf("new user created: %s", user.Uuid)
		return nil
	})

	return user, err
}

func (service *UserServiceImpl) GetAll(ctx context.Context) ([]UserEntity, error) {
	u, err := service.datastore.GetAllUsers(ctx)
	if err != nil {
		log.Error().Err(err).Msg("fetching all users failed")
		return []UserEntity{}, err
	}

	users := []UserEntity{}
	for _, user := range u {
		users = append(users, UserCredentialsToUserEntity(user.User, user.UserCredentials))
	}

	return users, nil
}

func (service *UserServiceImpl) GetByEmail(ctx context.Context, email string) (UserEntity, error) {
	u, err := service.datastore.GetUserByEmail(ctx, email)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with email %s", email)
		return UserEntity{}, err
	}

	return UserCredentialsToUserEntity(u.User, u.UserCredentials), nil
}

func (service *UserServiceImpl) GetByID(ctx context.Context, id int64) (UserEntity, error) {
	u, err := service.datastore.GetUserByID(ctx, id)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with id %d", id)
		return UserEntity{}, err
	}

	return UserCredentialsToUserEntity(u.User, u.UserCredentials), nil
}

func (service *UserServiceImpl) GetByUUID(ctx context.Context, uuid string) (UserEntity, error) {
	u, err := service.datastore.GetUserByUUID(ctx, uuid)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with UUID %s", uuid)
		return UserEntity{}, err
	}

	return UserToUserEntity(u), nil
}

func (service *UserServiceImpl) GetByOauthProvider(ctx context.Context, provider oauthprovider.OauthProvider, externalUserID string) (UserEntity, error) {
	p := db.GetUserByOauthProviderParams{
		ExternalUserID:  externalUserID,
		OauthProviderID: oauthprovider.OauthProviderNameToID[provider.String()],
	}

	u, err := service.datastore.GetUserByOauthProvider(ctx, p)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with provider %s and external User ID %s", provider, externalUserID)
		return UserEntity{}, err
	}

	return OauthUserToUserEntity(u.User, u.OauthUser), nil
}

func (service *UserServiceImpl) CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (service *UserServiceImpl) GetByVerifyEmailToken(ctx context.Context, token string) (UserEntity, error) {
	dbUser, err := service.datastore.GetUserByVerifyEmailToken(ctx, token)
	u := UserWithVerifyEmailTokenToUserEntity(dbUser.User, VerifyEmailToken{
		Token:     dbUser.VerifyEmailToken.Token,
		ExpiresAt: dbUser.VerifyEmailToken.ExpiresAt,
	})
	return u, err
}

func (service *UserServiceImpl) UpdateIsEmailVerified(ctx context.Context, userID int64) error {
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
