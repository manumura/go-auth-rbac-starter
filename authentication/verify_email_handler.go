package authentication

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

type VerifyEmailHandler struct {
	VerifyEmailService
	config.Config
	*validator.Validate
}

func NewVerifyEmailHandler(service VerifyEmailService, config config.Config, validate *validator.Validate) VerifyEmailHandler {
	return VerifyEmailHandler{
		service,
		config,
		validate,
	}
}

// @BasePath /api
// VerifyEmail godoc
// @Summary verify email
// @Description verify email
// @Tags verify email
// @Accept json
// @Produce json
// @Param VerifyEmailRequest body VerifyEmailRequest true "Verify Email Request"
// @Success 200 {object} security.AuthenticatedUser
// @Failure 400 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/verify-email [post]
func (h *VerifyEmailHandler) VerifyEmail(ctx *gin.Context) {
	log.Info().Msg("update user is email verified by token")
	var req VerifyEmailRequest
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

	log.Info().Msgf("find user by verify email token: %s", req.Token)
	u, err := h.GetUserByVerifyEmailToken(ctx, req.Token)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	tokenExpiresAt, err := time.Parse(time.DateTime, u.VerifyEmailToken.ExpiresAt)
	if err != nil {
		log.Error().Err(err).Msg("error parsing token expiry time")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	now := time.Now().UTC()
	if tokenExpiresAt.Before(now) {
		log.Error().Msg("token already expired")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrTokenExpired, http.StatusBadRequest))
		return
	}

	log.Info().Msgf("update user is email verified by user ID: %d", u.ID)
	err = h.UpdateIsEmailVerified(ctx, u.ID)
	if err != nil {
		log.Error().Err(err).Msg("failed to verify email")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	authenticatedUser := user.ToAuthenticatedUser(u)
	ctx.JSON(http.StatusOK, authenticatedUser)
}
