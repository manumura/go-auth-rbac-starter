package user

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (db.User, error)
	GetByEmail(ctx context.Context, email string) (db.User, error)
	CheckPassword(password string, hashedPassword string) error
}

type UserServiceImpl struct {
	datastore db.DataStore
}

func NewUserService(datastore db.DataStore) UserService {
	return &UserServiceImpl{
		datastore: datastore,
	}
}

func (service *UserServiceImpl) Create(ctx context.Context, req CreateUserRequest) (db.User, error) {
	now := time.Now().UTC()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		return db.User{}, err
	}

	p := db.CreateUserParams{
		Uuid:      uuid.New().String(),
		Name:      req.Name,
		Email:     req.Email,
		Password:  string(hashedPassword),
		IsActive:  1,
		RoleID:    role.RoleNameToID[req.Role.String()],
		CreatedAt: now.Format(time.DateTime),
	}

	u, err := service.datastore.CreateUser(ctx, p)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		return db.User{}, err
	}

	return u, nil
}

func (service *UserServiceImpl) GetByEmail(ctx context.Context, email string) (db.User, error) {
	u, err := service.datastore.GetUserByEmail(ctx, email)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		return db.User{}, err
	}

	return u, nil
}

func (service *UserServiceImpl) CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
