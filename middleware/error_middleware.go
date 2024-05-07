package middleware

import (
	"errors"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
)

type errorToResponseMap map[error]func(ctx *gin.Context, err error)

type errorMap struct {
	Errors   []error
	Response func(ctx *gin.Context, err error)
}

var ErrorToResponseMap = mapErrorsToResponse(
	errorMap{
		Errors:   []error{exception.ErrNotFound},
		Response: exception.NotFoundErrorHandler,
	},
	errorMap{
		Errors:   []error{exception.ErrAlreadyExists, exception.ErrInvalidRequest},
		Response: exception.BadRequestErrorHandler,
	},
	errorMap{
		Errors:   []error{exception.ErrInvalidPassword},
		Response: exception.UnauthorizedErrorHandler,
	},
	errorMap{
		Errors:   []error{exception.ErrInternal, exception.ErrCannotCreateUser},
		Response: exception.InternalServerErrorHandler,
	},
)

func mapErrorsToResponse(errMappings ...errorMap) errorToResponseMap {
	m := make(errorToResponseMap)

	for _, errorMapping := range errMappings {
		response := errorMapping.Response
		errors := errorMapping.Errors

		for _, err := range errors {
			m[err] = response
		}
	}
	return m
}

func ErrorHandlerV2(errMap errorToResponseMap) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()

		lastErr := context.Errors.Last()
		if lastErr == nil {
			return
		}

		h := errMap[lastErr.Err]
		h(context, lastErr.Err)
	}
}

type errorMapping struct {
	fromErrors   []error
	toStatusCode int
	toResponse   func(ctx *gin.Context, err error)
}

// Thanks to https://github.com/josephwoodward/gin-errorhandling
// ErrorHandler is middleware that enables you to configure error handling from a centralised place via its fluent API.
func ErrorHandler(errMap ...*errorMapping) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()

		lastErr := context.Errors.Last()
		if lastErr == nil {
			return
		}

		for _, errorMapping := range errMap {
			for _, err := range errorMapping.fromErrors {
				// if lastErr.Err == err || isType(lastErr.Err, err) {
				if errors.Is(err, lastErr.Err) || isType(lastErr.Err, err) {
					errorMapping.toResponse(context, lastErr.Err)
				}
			}
		}
	}
}

func isType(a, b interface{}) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

// ToStatusCode specifies the status code returned to a caller when the error is handled.
func (r *errorMapping) ToStatusCode(statusCode int) *errorMapping {
	r.toStatusCode = statusCode
	r.toResponse = func(ctx *gin.Context, err error) {
		ctx.Status(statusCode)
	}
	return r
}

// ToResponse provides more control over the returned response when an error is matched.
func (r *errorMapping) ToResponse(response func(ctx *gin.Context, err error)) *errorMapping {
	r.toResponse = response
	return r
}

// Map enables you to map errors to a given response status code or response body.
func Map(err ...error) *errorMapping {
	return &errorMapping{
		fromErrors: err,
	}
}
