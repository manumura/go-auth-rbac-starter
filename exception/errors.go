package exception

import "errors"

var (
	ErrNotFound         = errors.New("resource could not be found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrInvalidPassword  = errors.New("username or password is invalid")
	ErrInvalidRequest   = errors.New("request is invalid")
	ErrCannotCreateUser = errors.New("cannot create user")
	ErrInternal         = errors.New("internal server error")
)
