package profile

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/manumura/go-auth-rbac-starter/utils"
)

type ProfileService interface {
	GetProfileByUserUuid(ctx context.Context, userUUID uuid.UUID) (user.User, error)
	UpdateProfileByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateProfileParams) (user.UserEntity, error)
	UpdatePasswordByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdatePasswordParams) (user.UserEntity, error)
	UpdateImageByUserUuid(ctx context.Context, userUUID uuid.UUID, req UpdateImageParams) (user.UserEntity, error)
	DeleteProfileByUserUuid(ctx context.Context, userUUID uuid.UUID) (user.UserEntity, error)
	PushUserEvent(event user.UserChangeEvent)
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

func (service *ProfileServiceImpl) GetProfileByUserUuid(ctx context.Context, userUUID uuid.UUID) (user.User, error) {
	u, err := service.userService.GetByUUID(ctx, userUUID.String())
	if err != nil {
		return user.User{}, exception.ErrNotFound
	}

	return user.ToUser(u), err
}

func (service *ProfileServiceImpl) UpdateProfileByUserUuid(ctx context.Context, userUUID uuid.UUID, p UpdateProfileParams) (user.UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	params := db.UpdateUserParams{
		Uuid:      userUUID.String(),
		Name:      sql.NullString{String: p.Name, Valid: true},
		UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
	}
	dbUser, err := service.datastore.UpdateUser(ctx, params)
	if err != nil {
		return user.UserEntity{}, err
	}

	u := user.UserToUserEntity(dbUser)
	return u, err
}

func (service *ProfileServiceImpl) UpdatePasswordByUserUuid(ctx context.Context, userUUID uuid.UUID, p UpdatePasswordParams) (user.UserEntity, error) {
	u, err := service.userService.GetByUUID(ctx, userUUID.String())
	if err != nil {
		return user.UserEntity{}, exception.ErrNotFound
	}

	err = service.userService.CheckPassword(p.OldPassword, u.UserCredentials.Password)
	if err != nil {
		return user.UserEntity{}, exception.ErrInvalidRequest
	}

	hashedPassword, err := utils.CreateHash(p.NewPassword)
	if err != nil {
		return user.UserEntity{}, err
	}

	params := db.UpdateUserCredentialsParams{
		UserID:   u.ID,
		Password: sql.NullString{String: string(hashedPassword), Valid: true},
	}
	_, err = service.datastore.UpdateUserCredentials(ctx, params)
	if err != nil {
		return user.UserEntity{}, err
	}

	return u, err
}

func (service *ProfileServiceImpl) UpdateImageByUserUuid(ctx context.Context, userUUID uuid.UUID, p UpdateImageParams) (user.UserEntity, error) {
	now := time.Now().UTC()
	nowAsString := now.Format(time.DateTime)

	params := db.UpdateUserParams{
		Uuid:      userUUID.String(),
		ImageID:   sql.NullString{String: p.ImageID, Valid: true},
		ImageUrl:  sql.NullString{String: p.ImageURL, Valid: true},
		UpdatedAt: sql.NullString{String: nowAsString, Valid: true},
	}
	dbUser, err := service.datastore.UpdateUser(ctx, params)
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

func (service *ProfileServiceImpl) PushUserEvent(event user.UserChangeEvent) {
	service.userService.PushUserEvent(event)
}
