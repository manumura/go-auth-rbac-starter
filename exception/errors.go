package exception

import "errors"

var (
	ErrNotFound         = errors.New("resource be found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrInvalidPassword  = errors.New("username or password is invalid")
	ErrInvalidRequest   = errors.New("request is invalid")
	ErrCannotCreateUser = errors.New("cannot create user")
	ErrInternalServer   = errors.New("internal server error")
)
