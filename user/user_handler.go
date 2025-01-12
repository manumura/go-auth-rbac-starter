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

	u, err := h.GetByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	if u.Uuid != uuid.Nil {
		log.Error().Msg("email already exists")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
		return
	}

	user, err := h.Create(ctx, CreateUserRequest{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Role:     role.USER,
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

// TODO Add query params
func (h *UserHandler) GetAllUsers(ctx *gin.Context) {
	u, err := h.GetAll(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUsers := ToAuthenticatedUsers(u)
	ctx.JSON(http.StatusOK, authenticatedUsers)
}
