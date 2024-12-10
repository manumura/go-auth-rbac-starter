package message

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/rs/zerolog/log"
	gomail "gopkg.in/gomail.v2"
)

const templateDir = "message/templates"
const verifyEmailTemplate = "verify-email"
const newUserEmailTemplate = "new-user"

var verifyEmailSubject = map[string]string{
	"en": "Verify your MyApp email!",
	"fr": "Vérifiez votre email MyApp!",
}

var newUserEmailSubject = map[string]string{
	"en": "New MyApp user!",
	"fr": "Nouvel utilisateur MyApp!",
}

type EmailService interface {
	SendEmail(to string, subject string, body string) error
	SendRegistrationEmail(to string, langCode string, token string) error
	SendNewUserEmail(to string, langCode string, newUserEmail string) error
}

type EmailServiceImpl struct {
	config config.Config
}

func NewEmailService(config config.Config) EmailService {
	return &EmailServiceImpl{
		config: config,
	}
}

func (service *EmailServiceImpl) SendRegistrationEmail(to string, langCode string, token string) error {
	log.Info().Msgf("send registration email to: %s", to)

	if to == "" {
		return fmt.Errorf("email address is required")
	}

	if token == "" {
		return fmt.Errorf("token is required")
	}

	if langCode == "" {
		langCode = "en"
	}

	// Read template file
	// fmt.Println(os.Getwd())
	file := fmt.Sprintf("%s/%s-%s.html", templateDir, verifyEmailTemplate, langCode)
	tmpl, err := template.ParseFiles(file)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse email template")
		return err
	}

	// Define data for template
	data := struct {
		VerifyEmailLink string
	}{
		VerifyEmailLink: fmt.Sprintf("%s/verify-email?token=%s", service.config.ClientAppUrl, token),
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		log.Error().Err(err).Msg("failed to execute email template")
		return err
	}

	subject := verifyEmailSubject[langCode]
	return service.SendEmail(to, subject, body.String())
}

func (service *EmailServiceImpl) SendNewUserEmail(to string, langCode string, newUserEmail string) error {
	log.Info().Msgf("send new user email to: %s", to)

	if to == "" {
		return fmt.Errorf("to email address is required")
	}

	if newUserEmail == "" {
		return fmt.Errorf("new user email address is required")
	}

	if langCode == "" {
		langCode = "en"
	}

	// Read template file
	file := fmt.Sprintf("%s/%s-%s.html", templateDir, newUserEmailTemplate, langCode)
	tmpl, err := template.ParseFiles(file)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse email template")
		return err
	}

	// Define data for template
	data := struct {
		NewUserEmail string
	}{
		NewUserEmail: newUserEmail,
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		log.Error().Err(err).Msg("failed to execute email template")
		return err
	}

	subject := newUserEmailSubject[langCode]
	return service.SendEmail(to, subject, body.String())
}

func (service *EmailServiceImpl) SendEmail(to string, subject string, body string) error {
	c := service.config
	m := gomail.NewMessage()

	m.SetHeader("From", c.SmtpFrom)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	m.SetBody("text/html", body)

	d := gomail.NewDialer(c.SmtpHost, c.SmtpPort, c.SmtpUser, c.SmtpPassword)
	err := d.DialAndSend(m)
	if err != nil {
		log.Error().Err(err).Msg("failed to send email")
	}

	return err
}
