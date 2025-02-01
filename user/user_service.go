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
	Create(ctx context.Context, p CreateUserParams) (UserEntity, error)
	CreateOauth(ctx context.Context, p CreateOauthUserParams) (UserEntity, error)
	GetAll(ctx context.Context, p GetUsersParams) ([]UserEntity, error)
	CountAll(ctx context.Context, p CountUsersParams) (int64, error)
	GetByEmail(ctx context.Context, email string) (UserEntity, error)
	GetByID(ctx context.Context, id int64) (UserEntity, error)
	GetByUUID(ctx context.Context, uuid string) (UserEntity, error)
	UpdateByUUID(ctx context.Context, uuid string, p UpdateUserParams) (UserEntity, error)
	DeleteByUUID(ctx context.Context, uuid string) error
	GetByOauthProvider(ctx context.Context, provider oauthprovider.OauthProvider, externalUserID string) (UserEntity, error)
	CheckPassword(password string, hashedPassword string) error
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

func (service *UserServiceImpl) Create(ctx context.Context, req CreateUserParams) (UserEntity, error) {
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
		var isEmailVerified int64 = 0
		if req.IsEmailVerified {
			isEmailVerified = 1
		}
		ucp := db.CreateUserCredentialsParams{
			UserID:          u.ID,
			Email:           req.Email,
			Password:        string(hashedPassword),
			IsEmailVerified: isEmailVerified,
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

		user = UserWithCredentialsAndVerifyEmailTokenToUserEntity(u, uc, VerifyEmailTokenEntity{
			Token:     token,
			ExpiresAt: expiresAt,
		})
		log.Info().Msgf("new user created: %s", user.Uuid)
		return nil
	})

	return user, err
}

func (service *UserServiceImpl) CreateOauth(ctx context.Context, req CreateOauthUserParams) (UserEntity, error) {
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
			Email:           sql.NullString{String: req.Email, Valid: true},
		}

		ou, err := q.CreateOauthUser(ctx, oup)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return err
		}

		user = UserWithOauthProviderToUserEntity(u, ou)
		log.Info().Msgf("new user created: %s", user.Uuid)
		return nil
	})

	return user, err
}

func (service *UserServiceImpl) GetAll(ctx context.Context, p GetUsersParams) ([]UserEntity, error) {
	params := db.GetAllUsersParams{
		Limit:  sql.NullInt64{Int64: int64(p.Limit), Valid: true},
		Offset: sql.NullInt64{Int64: int64(p.Offset), Valid: true},
	}
	if p.Role != nil {
		roleId := role.RoleNameToID[p.Role.String()]
		params.RoleID = sql.NullInt64{Int64: int64(roleId), Valid: true}
	}
	dbUsers, err := service.datastore.GetAllUsers(ctx, params)
	if err != nil {
		log.Error().Err(err).Msg("fetching all users failed")
		return []UserEntity{}, err
	}

	users := []UserEntity{}
	for _, dbUser := range dbUsers {
		u := db.GetUserByUUIDRow(dbUser)
		users = append(users, GetUserByUUIDRowToUserEntity(u))
	}

	return users, nil
}

func (service *UserServiceImpl) CountAll(ctx context.Context, p CountUsersParams) (int64, error) {
	r := sql.NullInt64{Int64: 0, Valid: false}
	if p.Role != nil {
		roleId := role.RoleNameToID[p.Role.String()]
		r = sql.NullInt64{Int64: int64(roleId), Valid: true}
	}
	c, err := service.datastore.CountAllUsers(ctx, r)
	if err != nil {
		log.Error().Err(err).Msg("counting all users failed")
		return 0, err
	}

	return c, nil
}

func (service *UserServiceImpl) GetByEmail(ctx context.Context, email string) (UserEntity, error) {
	u, err := service.datastore.GetUserByEmail(ctx, email)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with email %s", email)
		return UserEntity{}, err
	}

	return UserWithCredentialsToUserEntity(u.User, u.UserCredentials), nil
}

func (service *UserServiceImpl) GetByID(ctx context.Context, id int64) (UserEntity, error) {
	u, err := service.datastore.GetUserByID(ctx, id)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with id %d", id)
		return UserEntity{}, err
	}

	return UserToUserEntity(u.User), nil
}

func (service *UserServiceImpl) GetByUUID(ctx context.Context, uuid string) (UserEntity, error) {
	u, err := service.datastore.GetUserByUUID(ctx, uuid)
	if err != nil {
		log.Error().Err(err).Msgf("user not found with UUID %s", uuid)
		return UserEntity{}, err
	}

	user := GetUserByUUIDRowToUserEntity(u)
	return user, nil
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

	return UserWithOauthProviderToUserEntity(u.User, u.OauthUser), nil
}

func (service *UserServiceImpl) CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (service *UserServiceImpl) UpdateByUUID(ctx context.Context, uuid string, p UpdateUserParams) (UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	var user UserEntity
	err := service.datastore.ExecTx(ctx, func(q *db.Queries) error {
		var err error

		u, err := service.datastore.GetUserByUUID(ctx, uuid)
		if err != nil {
			log.Error().Err(err).Msgf("user not found with UUID %s", uuid)
			return err
		}

		uup := db.UpdateUserParams{}

		if p.Name != nil {
			uup.Name = sql.NullString{String: *p.Name, Valid: true}
		}

		if p.Role != nil {
			roleId := role.RoleNameToID[p.Role.String()]
			uup.RoleID = sql.NullInt64{Int64: int64(roleId), Valid: true}
		}

		if p.IsActive != nil {
			active := 0
			if *p.IsActive {
				active = 1
			}
			uup.IsActive = sql.NullInt64{Int64: int64(active), Valid: true}
		}

		if uup.Name.Valid || uup.RoleID.Valid || uup.IsActive.Valid {
			log.Info().Msgf("updating user with UUID %s", uuid)
			uup.Uuid = uuid
			uup.UpdatedAt = sql.NullString{String: nowAsString, Valid: true}

			_, err = service.datastore.UpdateUser(ctx, uup)
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return err
			}
		}

		uucp := db.UpdateUserCredentialsParams{}

		if p.Email != nil {
			uucp.Email = sql.NullString{String: *p.Email, Valid: true}
		}

		if p.Password != nil {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*p.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return err
			}

			uucp.Password = sql.NullString{String: string(hashedPassword), Valid: true}
		}

		if uucp.Email.Valid || uucp.Password.Valid {
			log.Info().Msgf("updating user credentials with user ID %d", u.ID)
			uucp.UserID = u.ID

			_, err = service.datastore.UpdateUserCredentials(ctx, uucp)
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return err
			}
		}

		log.Info().Msgf("user with UUID updated %s", u.Uuid)
		user = GetUserByUUIDRowToUserEntity(u)
		return nil
	})

	return user, err
}

func (service *UserServiceImpl) DeleteByUUID(ctx context.Context, uuid string) error {
	return service.datastore.DeleteUser(ctx, uuid)
}
