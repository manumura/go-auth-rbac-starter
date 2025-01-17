package user

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

type UserHandler struct {
	// https://stackoverflow.com/questions/28014591/nameless-fields-in-go-structs
	UserService
	message.EmailService
	config.Config
	*validator.Validate
}

func NewUserHandler(service UserService, emailService message.EmailService, config config.Config, validate *validator.Validate) UserHandler {
	return UserHandler{
		service,
		emailService,
		config,
		validate,
	}
}

func (h *UserHandler) Register(ctx *gin.Context) {
	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	if err := h.Validate.Struct(req); err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	isEmailExist, err := h.isEmailExist(ctx, req.Email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}
	if isEmailExist {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
		return
	}

	user, err := h.Create(ctx, CreateUserParams{
		Name:            req.Name,
		Email:           req.Email,
		Password:        req.Password,
		Role:            role.USER,
		IsEmailVerified: false,
	})

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUser := ToAuthenticatedUser(user)

	// Send email with link to verify email
	go h.EmailService.SendRegistrationEmail(user.UserCredentials.Email, "", user.VerifyEmailToken.Token)
	// if err != nil {
	// 	log.Error().Err(err).Msg("failed to send email")
	// 	ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
	// 	return
	// }

	// Send new user email to root user
	go h.EmailService.SendNewUserEmail(h.Config.SmtpFrom, "", user.UserCredentials.Email)

	ctx.JSON(http.StatusOK, authenticatedUser)
}

func (h *UserHandler) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	if err := h.Validate.Struct(req); err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	isEmailExist, err := h.isEmailExist(ctx, req.Email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}
	if isEmailExist {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
		return
	}

	generatedPassword := uuid.New().String()
	log.Info().Msgf("generated password: %s", generatedPassword)

	user, err := h.Create(ctx, CreateUserParams{
		Name:            req.Name,
		Email:           req.Email,
		Password:        generatedPassword,
		Role:            req.Role,
		IsEmailVerified: true,
	})

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUser := ToAuthenticatedUser(user)

	// Send email with generated password
	go h.EmailService.SendTemporaryPasswordEmail(user.UserCredentials.Email, "", generatedPassword)

	ctx.JSON(http.StatusOK, authenticatedUser)
}

// TODO Return type User + Add query params + handle multiple providers
func (h *UserHandler) GetAllUsers(ctx *gin.Context) {
	u, err := h.GetAll(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUsers := ToAuthenticatedUsers(u)
	ctx.JSON(http.StatusOK, authenticatedUsers)
}

func (h *UserHandler) GetUser(ctx *gin.Context) {
	userUuidAsString := ctx.Param("uuid")
	log.Info().Msgf("get user by uuid %s", userUuidAsString)

	_, err := uuid.Parse(userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.ErrorResponse(err, http.StatusNotFound))
		return
	}

	user := ToUser(u)
	ctx.JSON(http.StatusOK, user)
}

func (h *UserHandler) DeleteUser(ctx *gin.Context) {
	userUuidAsString := ctx.Param("uuid")
	log.Info().Msgf("delete user by uuid %s", userUuidAsString)

	_, err := uuid.Parse(userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.ErrorResponse(err, http.StatusNotFound))
		return
	}

	err = h.DeleteByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.ErrorResponse(err, http.StatusNotFound))
		return
	}

	user := ToUser(u)
	ctx.JSON(http.StatusOK, user)
}

func (h *UserHandler) isEmailExist(ctx *gin.Context, email string) (bool, error) {
	// Check if email already exists
	u, err := h.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return true, err
	}

	if u.Uuid != uuid.Nil {
		log.Error().Msg("email already exists")
		return true, nil
	}

	return false, nil
}
