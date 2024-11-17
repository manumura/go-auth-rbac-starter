package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

func UserCredentialsToUserEntity(user db.User, userCredentials db.UserCredentials) UserEntity {
	c, err := time.Parse(time.DateTime, user.CreatedAt)
	if err != nil {
		log.Error().Err(err).Msg("error parsing created at")
		c = time.Now()
	}

	var u time.Time
	if user.UpdatedAt.Valid {
		u, err = time.Parse(time.DateTime, user.UpdatedAt.String)
		if err != nil {
			log.Error().Err(err).Msg("error parsing updated at")
			u = time.Now()
		}
	}

	return UserEntity{
		ID:        user.ID,
		Uuid:      uuid.MustParse(user.Uuid),
		Name:      user.Name,
		IsActive:  user.IsActive == 1,
		ImageID:   user.ImageID.String,
		ImageUrl:  user.ImageUrl.String,
		Role:      role.Role(role.RoleIDToName[user.RoleID]),
		CreatedAt: &c,
		UpdatedAt: &u,
		UserCredentials: UserCredentials{
			Password:        userCredentials.Password,
			Email:           userCredentials.Email,
			IsEmailVerified: userCredentials.IsEmailVerified == 1,
		},
	}
}

func ToAuthenticatedUser(user UserEntity) AuthenticatedUser {
	authenticatedUser := AuthenticatedUser{}
	copier.Copy(&authenticatedUser, &user)
	return authenticatedUser
}

func ToAuthenticatedUsers(users []UserEntity) []AuthenticatedUser {
	authenticatedUsers := []AuthenticatedUser{}
	for _, u := range users {
		authenticatedUser := ToAuthenticatedUser(u)
		authenticatedUsers = append(authenticatedUsers, authenticatedUser)
	}
	return authenticatedUsers
}

func OauthUserToUserEntity(user db.User, oauthUser db.OauthUser) UserEntity {
	c, err := time.Parse(time.DateTime, user.CreatedAt)
	if err != nil {
		log.Error().Err(err).Msg("error parsing created at")
		c = time.Now()
	}

	var u time.Time
	if user.UpdatedAt.Valid {
		u, err = time.Parse(time.DateTime, user.UpdatedAt.String)
		if err != nil {
			log.Error().Err(err).Msg("error parsing updated at")
			u = time.Now()
		}
	}

	return UserEntity{
		ID:        user.ID,
		Uuid:      uuid.MustParse(user.Uuid),
		Name:      user.Name,
		IsActive:  user.IsActive == 1,
		ImageID:   user.ImageID.String,
		ImageUrl:  user.ImageUrl.String,
		Role:      role.Role(role.RoleIDToName[user.RoleID]),
		CreatedAt: &c,
		UpdatedAt: &u,
		OauthUserProvider: OauthUserProvider{
			OauthProviderID: oauthUser.OauthProviderID,
			ExternalUserID:  oauthUser.ExternalUserID,
			Email:           oauthUser.Email,
		},
	}
}
