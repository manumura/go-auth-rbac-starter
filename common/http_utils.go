package common

import (
	"net/url"

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
