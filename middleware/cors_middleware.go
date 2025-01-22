package middleware

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	// - No origin allowed by default
	// - GET,POST, PUT, HEAD methods
	// - Credentials share disabled
	// - Preflight requests cached for 12 hours
	cfg := cors.DefaultConfig()
	cfg.AllowOrigins = allowedOrigins
	cfg.AllowCredentials = true
	cfg.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "Accept-Encoding", "Accept", "Cache-Control", "X-CSRF-Token", "X-Requested-With", "pragma", "expires"}
	return cors.New(cfg)
}
