package user

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	CheckPassword(password string, hashedPassword string) error
}

type UserServiceImpl struct {
	// store      db.Store
}

func NewUserService() UserService {
	return &UserServiceImpl{
		// store:      store,
	}
}

func (service *UserServiceImpl) Create(ctx context.Context, req CreateUserRequest) (User, error) {
	now := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("gRPC server failed to serve")
		return User{}, err
	}

	user := User{
		Id:       index,
		Uuid:     uuid.New(),
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		IsActive: true,
		// ImageId:   "imageId",
		// ImageUrl:  "imageUrl",
		Role:      req.Role,
		CreatedAt: &now,
		// UpdatedAt: time.Now(),
	}

	return user, nil
}

func (service *UserServiceImpl) GetByEmail(ctx context.Context, email string) (User, error) {
	for _, user := range Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, exception.ErrNotFound
}

func (service *UserServiceImpl) CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
