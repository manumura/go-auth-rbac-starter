package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/manumura/go-auth-rbac-starter/db"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

func UserToUserEntity(user db.User) UserEntity {
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
	}
}

func GetUserByUUIDRowToUserEntity(u db.GetUserByUUIDRow) UserEntity {
	dbUser := db.User{}
	copier.Copy(&dbUser, &u)
	user := UserToUserEntity(dbUser)

	if u.UserID.Valid {
		email := ""
		if u.Email.Valid {
			email = u.Email.String
		}
		password := ""
		if u.Password.Valid {
			password = u.Password.String
		}
		userCredentials := UserCredentialsEntity{
			Email:           email,
			Password:        password,
			IsEmailVerified: u.IsEmailVerified.Valid && u.IsEmailVerified.Int64 == 1,
		}
		user.UserCredentials = userCredentials
	}

	if u.UserID_2.Valid {
		providerEmail := ""
		if u.Email_2 != nil {
			providerEmail = u.Email_2.(string)
		}
		oauthUserProvider := OauthUserProviderEntity{
			ExternalUserID:  u.ExternalUserID.String,
			OauthProviderID: u.OauthProviderID.Int64,
			Email:           providerEmail,
		}
		user.OauthUserProvider = oauthUserProvider
	}

	return user
}

func UserWithCredentialsToUserEntity(user db.User, userCredentials db.UserCredentials) UserEntity {
	u := UserToUserEntity(user)
	u.UserCredentials = UserCredentialsEntity{
		Password:        userCredentials.Password,
		Email:           userCredentials.Email,
		IsEmailVerified: userCredentials.IsEmailVerified == 1,
	}
	return u
}

func UserWithCredentialsAndVerifyEmailTokenToUserEntity(user db.User, userCredentials db.UserCredentials, verifyEmailToken VerifyEmailTokenEntity) UserEntity {
	u := UserWithCredentialsToUserEntity(user, userCredentials)
	u.VerifyEmailToken = verifyEmailToken
	return u
}

func UserWithVerifyEmailTokenToUserEntity(user db.User, verifyEmailToken VerifyEmailTokenEntity) UserEntity {
	u := UserToUserEntity(user)
	u.VerifyEmailToken = verifyEmailToken
	return u
}

func UserWithResetPasswordTokenToUserEntity(user db.User, resetPasswordToken ResetPasswordTokenEntity) UserEntity {
	u := UserToUserEntity(user)
	u.ResetPasswordToken = resetPasswordToken
	return u
}

func UserWithOauthProviderToUserEntity(user db.User, oauthUser db.OauthUser) UserEntity {
	u := UserToUserEntity(user)
	u.OauthUserProvider = OauthUserProviderEntity{
		OauthProviderID: oauthUser.OauthProviderID,
		ExternalUserID:  oauthUser.ExternalUserID,
		Email:           oauthUser.Email.(string),
	}

	return u
}

func ToAuthenticatedUser(entity UserEntity) AuthenticatedUser {
	authenticatedUser := AuthenticatedUser{}
	copier.Copy(&authenticatedUser, &entity)
	return authenticatedUser
}

func ToAuthenticatedUsers(entities []UserEntity) []AuthenticatedUser {
	authenticatedUsers := []AuthenticatedUser{}
	for _, u := range entities {
		if u.Uuid != uuid.Nil {
			authenticatedUser := ToAuthenticatedUser(u)
			authenticatedUsers = append(authenticatedUsers, authenticatedUser)
		}
	}
	return authenticatedUsers
}

func ToOauthUserProvider(entity OauthUserProviderEntity) OauthUserProvider {
	o := OauthUserProvider{}
	copier.Copy(&o, &entity)

	o.OauthProvider = oauthprovider.OauthProviderIDToName[entity.OauthProviderID]
	return o
}

func ToOauthUserProviders(entities []OauthUserProviderEntity) []OauthUserProvider {
	providers := []OauthUserProvider{}
	for _, p := range entities {
		if p.OauthProviderID != 0 {
			provider := ToOauthUserProvider(p)
			providers = append(providers, provider)
		}
	}
	return providers
}

func ToUser(entity UserEntity) User {
	u := User{}
	copier.Copy(&u, &entity)

	email := entity.UserCredentials.Email
	if email != "" {
		u.Email = &email
	}

	providers := ToOauthUserProviders([]OauthUserProviderEntity{entity.OauthUserProvider})
	if len(providers) > 0 {
		u.Providers = &providers
	}
	return u
}
