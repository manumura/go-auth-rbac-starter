package middleware

import "net/http"

// Error messages
var (
	// CSRF errors
	ErrCSRFTokenMissing  = "CSRF token missing"
	ErrCSRFTokenInvalid  = "CSRF token invalid"
	ErrCSRFCookieMissing = "CSRF cookie missing"

	// Origin validation errors
	ErrInvalidOrigin = "Invalid origin"
)

// HTTP constants
const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
)

// Safe HTTP methods that don't require CSRF/Origin validation
var safeHttpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodTrace,
}
