package authentication

import (
	"github.com/jinzhu/copier"
	"github.com/manumura/go-auth-rbac-starter/user"
)

func ToAuthenticatedUser(entity user.UserEntity) AuthenticatedUser {
	authenticatedUser := AuthenticatedUser{}
	copier.Copy(&authenticatedUser, &entity)
	return authenticatedUser
}
