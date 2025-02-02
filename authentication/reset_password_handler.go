package authentication

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	"github.com/rs/zerolog/log"
)

type ResetPasswordHandler struct {
	ResetPasswordService
	message.EmailService
	config.Config
	*validator.Validate
}

func NewResetPasswordHandler(service ResetPasswordService, emailService message.EmailService, config config.Config, validate *validator.Validate) ResetPasswordHandler {
	return ResetPasswordHandler{
		service,
		emailService,
		config,
		validate,
	}
}

// @BasePath /api
// ForgotPassword godoc
// @Summary forgot password
// @Description forgot password
// @Tags reset password
// @Accept json
// @Produce json
// @Param ForgotPasswordRequest body ForgotPasswordRequest true "Forgot Password Request"
// @Success 200 {object} common.MessageResponse
// @Failure 400 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/forgot-password [post]
func (h *ResetPasswordHandler) ForgotPassword(ctx *gin.Context) {
	log.Info().Msg("forgot password for user with email")
	var req ForgotPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	if err := h.Validate.Struct(req); err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	log.Info().Msgf("find user by email: %s", req.Email)
	u, err := h.GetUserByEmail(ctx, req.Email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	t, err := h.CreateResetPasswordToken(ctx, u.ID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	log.Info().Msgf("[EMAIL][RESET_PWD] sending email to USER: %s", req.Email)
	go h.EmailService.SendResetPasswordEmail(req.Email, "", t.Token)

	ctx.JSON(http.StatusOK, common.MessageResponse{Message: "Reset password email sent"})
}

// @BasePath /api
// GetUserByToken godoc
// @Summary get user by token
// @Description get user by token
// @Tags reset password
// @Accept json
// @Produce json
// @Param token path string true "token"
// @Success 200 {object} AuthenticatedUser
// @Failure 400 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/token/{token} [get]
func (h *ResetPasswordHandler) GetUserByToken(ctx *gin.Context) {
	tokenAsString := ctx.Param("token")
	log.Info().Msgf("get user by token %s", tokenAsString)

	_, err := uuid.Parse(tokenAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetUserByResetPasswordToken(ctx, tokenAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	_, err = h.isTokenValid(u.ResetPasswordToken.ExpiresAt)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	authenticatedUser := ToAuthenticatedUser(u)
	ctx.JSON(http.StatusOK, authenticatedUser)
}

// @BasePath /api
// ResetPassword godoc
// @Summary reset password
// @Description reset password
// @Tags reset password
// @Accept json
// @Produce json
// @Param ResetPasswordRequest body ResetPasswordRequest true "Reset Password Request"
// @Success 200 {object} AuthenticatedUser
// @Failure 400 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/new-password [post]
func (h *ResetPasswordHandler) ResetPassword(ctx *gin.Context) {
	log.Info().Msg("reset password for user with token")
	var req ResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	_, err := uuid.Parse(req.Token)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	log.Info().Msgf("get user by token %s", req.Token)
	u, err := h.GetUserByResetPasswordToken(ctx, req.Token)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	_, err = h.isTokenValid(u.ResetPasswordToken.ExpiresAt)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	err = h.UpdatePassword(ctx, u.ID, req.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUser := ToAuthenticatedUser(u)
	ctx.JSON(http.StatusOK, authenticatedUser)
}

func (h *ResetPasswordHandler) isTokenValid(tokenExpiresAt string) (bool, error) {
	t, err := time.Parse(time.DateTime, tokenExpiresAt)
	if err != nil {
		log.Error().Err(err).Msg("error parsing token expiry time")
		return false, err
	}

	now := time.Now().UTC()
	if t.Before(now) {
		log.Error().Msg("token already expired")
		return false, exception.ErrTokenExpired
	}

	return true, nil
}
