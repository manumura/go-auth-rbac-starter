package captcha

// Uses https://github.com/go-playground/validator for validation
type ValidateCaptchaRequest struct {
	Token string `json:"token" validate:"required"`
}
