package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/captcha"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/profile"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/storage"
	"github.com/manumura/go-auth-rbac-starter/user"
)

const (
	prefix = "/api"
)

func (server *HttpServer) SetupRouter(config config.Config, validate *validator.Validate) *gin.Engine {
	userService := user.NewUserService(server.datastore)
	authenticationService := authentication.NewAuthenticationService(server.datastore)
	verifyEmailService := authentication.NewVerifyEmailService(server.datastore, userService)
	resetPasswordService := authentication.NewResetPasswordService(server.datastore, userService)
	storageService := storage.NewStorageService()
	profileService := profile.NewProfileService(server.datastore, userService)
	emailService := message.NewEmailService(config)

	userHandler := user.NewUserHandler(userService, emailService, config, validate)
	authenticationHandler := authentication.NewAuthenticationHandler(userService, authenticationService, config, validate)
	verifyEmailHandler := authentication.NewVerifyEmailHandler(verifyEmailService, config, validate)
	resetPasswordHandler := authentication.NewResetPasswordHandler(resetPasswordService, emailService, config, validate)
	captchaHandler := captcha.NewCaptchaHandler(config, validate)
	profileHandler := profile.NewProfileHandler(profileService, storageService, config, validate)

	router := gin.Default()
	router.Use(gin.CustomRecovery(exception.UncaughtErrorHandler))
	router.Use(middleware.SecurityMiddleware())

	// - No origin allowed by default
	// - GET,POST, PUT, HEAD methods
	// - Credentials share disabled
	// - Preflight requests cached for 12 hours
	cfg := cors.DefaultConfig()
	// TODO change to env variable
	cfg.AllowOrigins = []string{"http://localhost:3001"}
	cfg.AllowCredentials = true
	router.Use(cors.New(cfg))

	publicRouterGroup := router.Group(prefix)
	publicRouterGroup.GET("/v1/index", server.index)
	publicRouterGroup.GET("/v1/info", server.info)
	publicRouterGroup.POST("/v1/register", userHandler.Register)
	publicRouterGroup.POST("/v1/login", authenticationHandler.Login)
	publicRouterGroup.POST("/v1/oauth2/facebook", authenticationHandler.Oauth2FacebookLogin)
	publicRouterGroup.POST("/v1/oauth2/google", authenticationHandler.Oauth2GoogleLogin)
	publicRouterGroup.POST("/v1/verify-email", verifyEmailHandler.VerifyEmail)
	publicRouterGroup.POST("/v1/recaptcha", captchaHandler.ValidateCaptcha)
	publicRouterGroup.POST("/v1/forgot-password", resetPasswordHandler.ForgotPassword)
	publicRouterGroup.GET("/v1/token/:token", resetPasswordHandler.GetUserByToken)
	publicRouterGroup.POST("/v1/new-password", resetPasswordHandler.ResetPassword)

	logoutRoutes := router.Group(prefix).Use(middleware.LogoutAuthMiddleware(authenticationService, userService))
	logoutRoutes.POST("/v1/logout", authenticationHandler.Logout)

	refreshTokenRoutes := router.Group(prefix).Use(middleware.RefreshAuthMiddleware(authenticationService, userService))
	refreshTokenRoutes.POST("/v1/refresh-token", authenticationHandler.RefreshToken)

	authRoutes := router.Group(prefix).Use(middleware.AuthMiddleware(authenticationService, userService))
	authRoutes.GET("/v1/profile", profileHandler.GetProfile)
	authRoutes.PUT("/v1/profile", profileHandler.UpdateProfile)
	authRoutes.PUT("/v1/profile/password", profileHandler.UpdatePassword)
	authRoutes.PUT("/v1/profile/image", profileHandler.UpdateImage)
	authRoutes.DELETE("/v1/profile", profileHandler.DeleteProfile)

	adminRoutes := router.Group(prefix).Use(middleware.AuthMiddleware(authenticationService, userService)).Use(middleware.RoleMiddleware([]role.Role{role.ADMIN}))
	// TODO
	adminRoutes.POST("/v1/users", userHandler.CreateUser)
	adminRoutes.GET("/v1/users", userHandler.GetAllUsers)
	adminRoutes.GET("/v1/users/:uuid", userHandler.GetUser)
	// adminRoutes.PUT("/v1/users/:uuid", userHandler.UpdateUser)
	adminRoutes.DELETE("/v1/users/:uuid", userHandler.DeleteUser)

	return router
}
