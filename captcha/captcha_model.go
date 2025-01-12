package captcha

// Uses https://github.com/go-playground/validator for validation
type CaptchaRequest struct {
	Token string `json:"token" validate:"required"`
}
