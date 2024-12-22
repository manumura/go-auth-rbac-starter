package api

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/profile"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/user"
)

func (server *HttpServer) SetupRouter(config config.Config, validate *validator.Validate) *gin.Engine {
	userService := user.NewUserService(server.datastore)
	authenticationService := authentication.NewAuthenticationService(server.datastore)
	emailService := message.NewEmailService(config)

	userHandler := user.NewUserHandler(userService, emailService, config, validate)
	authenticationHandler := authentication.NewAuthenticationHandler(userService, authenticationService, config, validate)
	profileHandler := profile.NewProfileHandler(userService)

	router := gin.Default()
	router.Use(gin.CustomRecovery(exception.UncaughtErrorHandler))
	router.Use(middleware.SecurityMiddleware())

	publicRouterGroup := router.Group("/api/v1")
	publicRouterGroup.GET("/index", server.index)
	publicRouterGroup.POST("/register", userHandler.Register)
	publicRouterGroup.POST("/login", authenticationHandler.Login)
	// TODO refresh token
	publicRouterGroup.POST("/oauth2/facebook", authenticationHandler.Oauth2FacebookLogin)
	publicRouterGroup.POST("/oauth2/google", authenticationHandler.Oauth2GoogleLogin)
	publicRouterGroup.POST("/verify-email", authenticationHandler.VerifyEmail)

	logoutRoutes := publicRouterGroup.Use(middleware.LogoutMiddleware(authenticationService, userService))
	logoutRoutes.POST("/logout", authenticationHandler.Logout)

	authRoutes := publicRouterGroup.Use(middleware.AuthMiddleware(authenticationService, userService))
	authRoutes.GET("/profile", profileHandler.GetProfile)

	adminRoutes := authRoutes.Use(middleware.RoleMiddleware([]role.Role{role.ADMIN}))
	adminRoutes.GET("/users", userHandler.GetAllUsers)

	return router
}
