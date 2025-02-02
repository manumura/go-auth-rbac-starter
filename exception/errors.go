package exception

import (
	"errors"
	"net/http"
)

var (
	ErrNotFound              = errors.New("resource not found")
	ErrAlreadyExists         = errors.New("resource already exists")
	ErrLogin                 = errors.New("invalid email or password")
	ErrInvalidRequest        = errors.New("request is invalid")
	ErrInvalidFileExtension  = errors.New("file extension is invalid")
	ErrCannotCreateUser      = errors.New("cannot create user")
	ErrInternalServer        = errors.New("internal server error")
	ErrorInvalidAccessToken  = errors.New("invalid access token")
	ErrorInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidEmail          = errors.New("invalid email")
	ErrForbidden             = errors.New("user not allowed to access this resource")
	ErrUnauthorized          = errors.New("user not authenticated")
	ErrTokenExpired          = errors.New("token expired")
)

type ErrorResponse struct {
	Message    string `json:"message"`
	Error      string `json:"error"`
	StatusCode int    `json:"statusCode"`
}

func GetErrorResponse(err error, statusCode int) ErrorResponse {
	return ErrorResponse{
		Message:    err.Error(),
		Error:      http.StatusText(statusCode),
		StatusCode: statusCode,
	}
}
