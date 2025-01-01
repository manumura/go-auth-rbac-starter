package authentication

import (
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/user"
)

type VerifyEmailService interface {
}

type VerifyEmailServiceImpl struct {
	datastore   db.DataStore
	userService user.UserService
}

func NewVerifyEmailService(datastore db.DataStore, userService user.UserService) VerifyEmailService {
	return &VerifyEmailServiceImpl{
		datastore:   datastore,
		userService: userService,
	}
}
