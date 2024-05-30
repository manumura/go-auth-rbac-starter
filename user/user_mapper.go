package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

func ToUserResponse(user db.User) UserResponse {
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

	return UserResponse{
		Uuid:      uuid.MustParse(user.Uuid),
		Name:      user.Name,
		Email:     user.Email,
		IsActive:  user.IsActive == 1,
		ImageID:   user.ImageID.String,
		ImageUrl:  user.ImageUrl.String,
		Role:      role.Role(role.RoleIDToName[user.RoleID]),
		CreatedAt: &c,
		UpdatedAt: &u,
	}
}

func ToUserResponseList(users []db.User) []UserResponse {
	userResponseList := []UserResponse{}
	for _, u := range users {
		userResponse := ToUserResponse(u)
		userResponseList = append(userResponseList, userResponse)
	}
	return userResponseList
}
