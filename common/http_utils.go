package common

import (
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func GetOriginFromHeader(ctx *gin.Context) string {
	// Get Origin header (preferred)
	origin := ctx.GetHeader("Origin")

	// Fall back to Referer header if Origin is not present
	if origin == "" {
		referer := ctx.GetHeader("Referer")
		if referer != "" {
			parsedReferer, err := url.Parse(referer)
			if err == nil {
				origin = parsedReferer.Scheme + "://" + parsedReferer.Host
			}
		}
	}

	log.Info().Str("origin", origin).
		Str("method", ctx.Request.Method).
		Str("path", ctx.Request.URL.Path).
		Msg("Extracted origin from request")
	return origin
}

// isOriginAllowed checks if the given origin is in the allowed list
func IsOriginAllowed(origin string, allowedOrigins []string) bool {
	// Normalize origin (remove trailing slash if present)
	origin = normalizeOrigin(origin)

	for _, allowed := range allowedOrigins {
		normalizedAllowed := normalizeOrigin(allowed)

		// Exact match
		if origin == normalizedAllowed {
			return true
		}

		// Wildcard match (e.g., "*" allows all origins - use with caution)
		if normalizedAllowed == "*" {
			return true
		}
	}

	return false
}

// normalizeOrigin removes trailing slashes and converts to lowercase
func normalizeOrigin(origin string) string {
	if len(origin) > 0 && origin[len(origin)-1] == '/' {
		origin = origin[:len(origin)-1]
	}
	return strings.ToLower(origin)
}
