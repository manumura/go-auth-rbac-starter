package exception

import (
	"errors"

	"github.com/gin-gonic/gin"
)

var (
	ErrNotFound         = errors.New("resource not found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrInvalidPassword  = errors.New("username or password is invalid")
	ErrInvalidRequest   = errors.New("request is invalid")
	ErrCannotCreateUser = errors.New("cannot create user")
	ErrInternalServer   = errors.New("internal server error")
)

func ErrorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
