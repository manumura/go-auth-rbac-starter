package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

func ToUser(user db.User, userCredentials db.UserCredentials) User {
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

	return User{
		ID:        user.ID,
		Uuid:      uuid.MustParse(user.Uuid),
		Name:      user.Name,
		IsActive:  user.IsActive == 1,
		ImageID:   user.ImageID.String,
		ImageUrl:  user.ImageUrl.String,
		Role:      role.Role(role.RoleIDToName[user.RoleID]),
		CreatedAt: &c,
		UpdatedAt: &u,
		Password:  userCredentials.Password,
		Email:     userCredentials.Email,
	}
}

func ToAuthenticatedUser(user User) AuthenticatedUser {
	authenticatedUser := AuthenticatedUser{}
	copier.Copy(&authenticatedUser, &user)
	return authenticatedUser
}

func ToAuthenticatedUsers(users []User) []AuthenticatedUser {
	authenticatedUsers := []AuthenticatedUser{}
	for _, u := range users {
		authenticatedUser := ToAuthenticatedUser(u)
		authenticatedUsers = append(authenticatedUsers, authenticatedUser)
	}
	return authenticatedUsers
}
