package exception

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	ErrNotFound              = errors.New("resource not found")
	ErrAlreadyExists         = errors.New("resource already exists")
	ErrLogin                 = errors.New("invalid email or password")
	ErrInvalidRequest        = errors.New("request is invalid")
	ErrCannotCreateUser      = errors.New("cannot create user")
	ErrInternalServer        = errors.New("internal server error")
	ErrorInvalidAccessToken  = errors.New("invalid access token")
	ErrorInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidEmail          = errors.New("invalid email")
	ErrForbidden             = errors.New("user not allowed to access this resource")
	ErrUnauthorized          = errors.New("user not authenticated")
	ErrTokenExpired          = errors.New("token expired")
)

func ErrorResponse(err error, statusCode int) gin.H {
	return gin.H{
		"message":    err.Error(),
		"error":      http.StatusText(statusCode),
		"statusCode": statusCode,
	}
}
