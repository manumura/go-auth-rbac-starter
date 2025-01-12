package profile

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"golang.org/x/crypto/bcrypt"
)

type ProfileService interface {
	UpdateProfileByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateProfileRequest) (user.UserEntity, error)
	UpdatePasswordByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdatePasswordRequest) (user.UserEntity, error)
	UpdateImageByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateImageRequest) (user.UserEntity, error)
	DeleteProfileByUserUuid(ctx context.Context, userUUID uuid.UUID) (user.UserEntity, error)
}

type ProfileServiceImpl struct {
	datastore   db.DataStore
	userService user.UserService
}

func NewProfileService(datastore db.DataStore, userService user.UserService) ProfileService {
	return &ProfileServiceImpl{
		datastore:   datastore,
		userService: userService,
	}
}

func (service *ProfileServiceImpl) UpdateProfileByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateProfileRequest) (user.UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	p := db.UpdateUserParams{
		Uuid:      userUUID.String(),
		Name:      sql.NullString{String: req.Name, Valid: true},
		UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
	}
	dbUser, err := service.datastore.UpdateUser(ctx, p)
	if err != nil {
		return user.UserEntity{}, err
	}

	u := user.UserToUserEntity(dbUser)
	return u, err
}

func (service *ProfileServiceImpl) UpdatePasswordByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdatePasswordRequest) (user.UserEntity, error) {
	u, err := service.userService.GetByUUID(ctx, userUUID.String())
	if err != nil {
		return user.UserEntity{}, exception.ErrNotFound
	}

	err = service.userService.CheckPassword(req.OldPassword, u.UserCredentials.Password)
	if err != nil {
		return user.UserEntity{}, exception.ErrInvalidRequest
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return user.UserEntity{}, err
	}

	p := db.UpdateUserPasswordParams{
		UserID:   u.ID,
		Password: string(hashedPassword),
	}
	err = service.datastore.UpdateUserPassword(ctx, p)
	if err != nil {
		return user.UserEntity{}, err
	}

	return u, err
}

func (service *ProfileServiceImpl) UpdateImageByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateImageRequest) (user.UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	p := db.UpdateUserParams{
		Uuid:      userUUID.String(),
		ImageID:   sql.NullString{String: req.ImageID, Valid: true},
		ImageUrl:  sql.NullString{String: req.ImageURL, Valid: true},
		UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
	}
	dbUser, err := service.datastore.UpdateUser(ctx, p)
	if err != nil {
		return user.UserEntity{}, err
	}

	u := user.UserToUserEntity(dbUser)
	return u, err
}

func (service *ProfileServiceImpl) DeleteProfileByUserUuid(ctx context.Context, userUUID uuid.UUID) (user.UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	p := db.UpdateUserParams{
		Uuid:      userUUID.String(),
		IsActive:  sql.NullInt64{Int64: 0, Valid: true},
		UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
	}
	dbUser, err := service.datastore.UpdateUser(ctx, p)
	if err != nil {
		return user.UserEntity{}, err
	}

	u := user.UserToUserEntity(dbUser)
	return u, err
}
