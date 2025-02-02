package captcha

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/rs/zerolog/log"
)

type CaptchaHandler struct {
	config.Config
	*validator.Validate
}

func NewCaptchaHandler(config config.Config, validate *validator.Validate) CaptchaHandler {
	return CaptchaHandler{
		config,
		validate,
	}
}

type GoogleRecaptchaResponse struct {
	APKPackageName     string    `json:"apk_package_name"`
	Action             string    `json:"action"`
	ChallengeTimestamp time.Time `json:"challenge_ts"`
	ErrorCodes         []string  `json:"error-codes"`
	Hostname           string    `json:"hostname"`
	Score              float64   `json:"score"`
	Success            bool      `json:"success"`
}

// @BasePath /api
// ValidateCaptcha godoc
// @Summary validate captcha
// @Description validate captcha
// @Tags recaptcha
// @Accept json
// @Produce json
// @Param ValidateCaptchaRequest body ValidateCaptchaRequest true "Validate Captcha Request"
// @Success 200 {bool} success
// @Failure 400 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/recaptcha [post]
func (h *CaptchaHandler) ValidateCaptcha(ctx *gin.Context) {
	log.Info().Msg("validate captcha")
	var req ValidateCaptchaRequest
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

	url := fmt.Sprintf("https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s", h.Config.RecaptchaSecretKey, req.Token)
	resp, err := http.Post(url, "application/x-www-form-urlencoded", nil)
	if err != nil {
		log.Error().Err(err).Msg("error validating captcha")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	defer resp.Body.Close()
	var r GoogleRecaptchaResponse
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		log.Error().Err(err).Msg("error parsing reCAPTCHA V3 JSON response")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	log.Info().Msgf("reCAPTCHA V3 response: %+v", r)
	success := false
	if r.Score > 0.5 {
		success = true
	}

	ctx.JSON(http.StatusOK, success)
}
