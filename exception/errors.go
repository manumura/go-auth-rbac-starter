package exception

import "errors"

// TODO improve with dynamic error messages
// func New(message string) error {
// 	return errors.New(message)
// }

var (
	ErrNotFound         = errors.New("resource not found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrInvalidPassword  = errors.New("username or password is invalid")
	ErrInvalidRequest   = errors.New("request is invalid")
	ErrCannotCreateUser = errors.New("cannot create user")
	ErrInternalServer   = errors.New("internal server error")
)
