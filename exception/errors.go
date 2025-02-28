package exception

import (
	"errors"
	"net/http"
)

var (
	ErrNotFound              = errors.New("resource_not_found")
	ErrAlreadyExists         = errors.New("resource_already_exists")
	ErrLogin                 = errors.New("invalid_email_or_password")
	ErrEmailNotVerified      = errors.New("email_not_verified")
	ErrInvalidRequest        = errors.New("invalid_request")
	ErrInvalidFileExtension  = errors.New("invalid_file_extension")
	ErrInternalServer        = errors.New("internal_server_error")
	ErrorInvalidAccessToken  = errors.New("invalid_access_token")
	ErrorInvalidRefreshToken = errors.New("invalid_refresh_token")
	ErrInvalidEmail          = errors.New("invalid_email")
	ErrForbidden             = errors.New("forbidden")
	ErrUnauthorized          = errors.New("unauthorized")
	ErrTokenExpired          = errors.New("token_expired")
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
