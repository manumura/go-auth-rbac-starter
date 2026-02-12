package authentication

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/cache"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/cookie"
	"github.com/manumura/go-auth-rbac-starter/csrf"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"

	"golang.org/x/oauth2"
)

type AuthenticationHandler struct {
	user.UserService
	AuthenticationService
	message.EmailService
	config.Config
	*validator.Validate
	cacheService cache.CacheService
}

type authenticationToken struct {
	IdToken               string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

const (
	FacebookAuthURL    = "https://www.facebook.com/v22.0/dialog/oauth"
	FacebookTokenURL   = "https://graph.facebook.com/v22.0/oauth/access_token"
	FacebookProfileURL = "https://graph.facebook.com/v22.0/me"
)

var FacebookEndpoint = oauth2.Endpoint{
	AuthURL:  FacebookAuthURL,
	TokenURL: FacebookTokenURL,
}

func NewAuthenticationHandler(userService user.UserService, authenticationService AuthenticationService, emailService message.EmailService, config config.Config, validate *validator.Validate, cacheService cache.CacheService) AuthenticationHandler {
	return AuthenticationHandler{
		userService,
		authenticationService,
		emailService,
		config,
		validate,
		cacheService,
	}
}

// @BasePath /api
// Register godoc
// @Summary register user
// @Description register user
// @Tags authentication
// @Accept json
// @Produce json
// @Param RegisterRequest body RegisterRequest true "Register Request"
// @Success 200 {object} security.AuthenticatedUser
// @Failure 400 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/register [post]
func (h *AuthenticationHandler) Register(ctx *gin.Context) {
	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("invalid request")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	if err := h.Validate.Struct(req); err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	// Check if email already exists
	existingUser, err := h.GetByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Error().Err(err).Msg("failed to get user by email")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	if existingUser.Uuid != uuid.Nil {
		if existingUser.IsActive {
			log.Error().Msgf("email already exists: %s", req.Email)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
			return
		}

		log.Warn().Msgf("deleting inactive user with email %s", req.Email)
		err = h.DeleteByUUID(ctx, existingUser.Uuid.String())
		if err != nil {
			log.Error().Err(err).Msg("failed to delete inactive user")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
			return
		}
	}

	u, err := h.Create(ctx, user.CreateUserParams{
		Name:            req.Name,
		Email:           req.Email,
		Password:        req.Password,
		Role:            role.USER,
		IsEmailVerified: false,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create user")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	createdUser := user.ToUser(u)

	// Send email with link to verify email
	go h.EmailService.SendRegistrationEmail(u.UserCredentials.Email, "", u.VerifyEmailToken.Token)
	// if err != nil {
	// 	log.Error().Err(err).Msg("failed to send email")
	// 	ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
	// 	return
	// }

	// Send new user email to root user
	go h.EmailService.SendNewUserEmail(h.Config.SmtpFrom, "", u.UserCredentials.Email)

	e := user.NewUserChangeEvent(user.CREATED, createdUser, createdUser.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, createdUser)
}

// @BasePath /api
// Login godoc
// @Summary login
// @Description login
// @Tags authentication
// @Accept json
// @Produce json
// @Param LoginRequest body LoginRequest true "Login Request"
// @Success 200 {object} AuthenticationResponse
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/login [post]
func (h *AuthenticationHandler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("invalid request")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByEmail(ctx, req.Email)
	if err != nil {
		log.Error().Err(err).Msg("user not found")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	if !u.IsActive {
		log.Error().Msg("user is not active")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	// Comparing the password with the hash
	err = h.CheckPassword(req.Password, u.UserCredentials.Password)
	if err != nil {
		log.Error().Err(err).Msg("invalid password")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	if !u.UserCredentials.IsEmailVerified {
		log.Error().Msg("email is not verified")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrEmailNotVerified, http.StatusUnauthorized))
		return
	}

	authResponse, authenticatedUser, err := h.createAuthenticationTokens(u, ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to create authentication tokens")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// Generate session-bound CSRF token and store in Redis
	csrfToken, err := csrf.GenerateAndStoreSessionToken(ctx, h.cacheService, h.Config, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("failed to generate CSRF token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}
	// Set CSRF token in cookie
	csrf.SetCSRFCookie(ctx, csrfToken, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})

	cookie.SetAuthCookies(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	}, cookie.AuthCookieParams{
		AccessToken:          authResponse.AccessToken,
		RefreshToken:         authResponse.RefreshToken,
		AccessTokenExpiresAt: authResponse.AccessTokenExpiresAt,
		IdToken:              authResponse.IdToken,
	})
	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

// @BasePath /api
// RefreshToken godoc
// @Summary refresh token
// @Description refresh token
// @Tags authentication
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} AuthenticationResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/refresh-token [post]
func (h *AuthenticationHandler) RefreshToken(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	log.Info().Msgf("user %s token refresh", authenticatedUser.Uuid)
	if err != nil {
		log.Error().Err(err).Msg("cannot get user from context")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	u, err := h.GetByUUID(ctx, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("user not found")
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(exception.ErrNotFound, http.StatusNotFound))
		return
	}

	authResponse, authenticatedUser, err := h.createAuthenticationTokens(u, ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to create authentication tokens")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// Generate new session-bound CSRF token and store in Redis
	csrfToken, err := csrf.GenerateAndStoreSessionToken(ctx, h.cacheService, h.Config, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("failed to generate CSRF token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}
	// Set CSRF token in cookie
	csrf.SetCSRFCookie(ctx, csrfToken, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})

	cookie.SetAuthCookies(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	}, cookie.AuthCookieParams{
		AccessToken:          authResponse.AccessToken,
		RefreshToken:         authResponse.RefreshToken,
		AccessTokenExpiresAt: authResponse.AccessTokenExpiresAt,
		IdToken:              authResponse.IdToken,
	})
	log.Info().Msgf("user %s token refreshed", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

// @BasePath /api
// Logout godoc
// @Summary logout
// @Description logout
// @Tags authentication
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} AuthenticationResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/logout [post]
func (h *AuthenticationHandler) Logout(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("cannot get user from context")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	u, err := h.GetByUUID(ctx, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("user not found")
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(exception.ErrNotFound, http.StatusNotFound))
		return
	}

	err = h.DeleteAuthenticationTokenByUserID(ctx, u.ID)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete authentication token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	// Clean up CSRF token from Redis
	if err := csrf.DeleteSessionToken(ctx, h.cacheService, authenticatedUser.Uuid.String()); err != nil {
		log.Warn().Err(err).Msg("failed to delete CSRF token from cache")
		// Don't fail logout if CSRF token deletion fails
	}
	csrf.DeleteCSRFCookie(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})

	cookie.DeleteAuthCookies(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})
	log.Info().Msgf("user %s logged out", authenticatedUser.Uuid)
	ctx.JSON(http.StatusNoContent, nil)
}

// @BasePath /api
// Oauth2FacebookLogin godoc
// @Summary facebook login
// @Description facebook login
// @Tags authentication
// @Success 307
// @Failure 400 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/oauth2/facebook [get]
func (h *AuthenticationHandler) Oauth2FacebookLogin(ctx *gin.Context) {
	oAuth2Config := h.getFacebookOauth2Config(ctx)
	origin := common.GetOriginFromHeader(ctx)
	log.Info().Msgf("OAuth2 Facebook login initiated from origin: %s", origin)

	uuid := uuid.New().String()
	randomOAuthStateString := strings.Replace(uuid, "-", "", -1)
	cacheKey := "facebook:" + randomOAuthStateString
	err := h.cacheService.Set(ctx, cacheKey, origin, time.Minute*5)
	if err != nil {
		log.Error().Msgf("Error setting cache key: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	url := oAuth2Config.AuthCodeURL(randomOAuthStateString)
	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// @BasePath /api
// Oauth2FacebookLoginCallback godoc
// @Summary facebook login callback
// @Description facebook login callback
// @Tags authentication
// @Success 200 {object} AuthenticationResponse
// @Failure 400 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/oauth2/facebook/callback [get]
func (h *AuthenticationHandler) Oauth2FacebookLoginCallback(ctx *gin.Context) {
	code := ctx.Query("code")
	state := ctx.Query("state")
	errorResponse := ctx.Query("error")
	errorReason := ctx.Query("error_reason")
	errorDescription := ctx.Query("error_description")
	errorUrl := h.Config.ClientAppUrl + "/oauth/facebook/callback?error=callback_failed"

	if errorResponse != "" {
		log.Error().Msgf("error: %s, error_reason: %s, error_description: %s", errorResponse, errorReason, errorDescription)
		// ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}

	if code == "" {
		log.Error().Msg("code is empty")
		// ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}

	cacheKey := "facebook:" + state
	origin, err := h.cacheService.Get(ctx, cacheKey)
	if err == cache.ErrCacheMiss {
		log.Error().Msg("invalid oauth state")
		// ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	} else if err != nil {
		log.Error().Msgf("Error getting cache key: %v", err)
		// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}
	log.Info().Msgf("OAuth2 Facebook login callback from origin: %s", origin)

	err = h.cacheService.Delete(ctx, cacheKey)
	if err != nil {
		log.Error().Msgf("Error deleting cache key: %v", err)
	}

	oAuth2Config := h.getFacebookOauth2Config(ctx)
	token, err := oAuth2Config.Exchange(ctx, code)
	if err != nil || token == nil {
		log.Error().Err(err).Msg("failed to exchange token")
		// ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}

	fbUserDetails, fbUserDetailsError := getUserInfoFromFacebook(token.AccessToken)
	if fbUserDetailsError != nil {
		log.Error().Err(fbUserDetailsError).Msg("failed to get user details from facebook")
		// ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}

	authResponse, authenticatedUser, err := h.authenticate(fbUserDetails.ID, oauthprovider.FACEBOOK, fbUserDetails.Name, fbUserDetails.Email, ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to authenticate user")
		// statusCode := http.StatusInternalServerError
		// if err == exception.ErrLogin {
		// 	statusCode = http.StatusUnauthorized
		// }
		// ctx.AbortWithStatusJSON(statusCode, exception.GetErrorResponse(err, statusCode))
		ctx.Redirect(http.StatusTemporaryRedirect, errorUrl)
		return
	}

	// Generate session-bound CSRF token and store in Redis
	csrfToken, err := csrf.GenerateAndStoreSessionToken(ctx, h.cacheService, h.Config, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("failed to generate CSRF token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}
	// Set CSRF token in cookie
	csrf.SetCSRFCookie(ctx, csrfToken, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})

	cookie.SetAuthCookies(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	}, cookie.AuthCookieParams{
		AccessToken:          authResponse.AccessToken,
		RefreshToken:         authResponse.RefreshToken,
		AccessTokenExpiresAt: authResponse.AccessTokenExpiresAt,
		IdToken:              authResponse.IdToken,
	})
	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)

	url := h.Config.ClientAppUrl + "/oauth/facebook/callback?access_token=" + authResponse.AccessToken + "&refresh_token=" + authResponse.RefreshToken + "&id_token=" + authResponse.IdToken + "&expires_at=" + authResponse.AccessTokenExpiresAt.Format(time.RFC1123) + "&token_type=Bearer"
	ctx.Redirect(http.StatusTemporaryRedirect, url)
	// ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) getFacebookOauth2Config(ctx *gin.Context) *oauth2.Config {
	scheme := "http"
	if h.Config.Environment != "dev" {
		scheme = "https"
	}
	redirectURL := fmt.Sprintf("%s://%s%s", scheme, ctx.Request.Host, h.Config.FacebookRedirectUrl)
	log.Info().Msgf("Facebook Redirect URL: %s", redirectURL)

	return &oauth2.Config{
		ClientID:     h.Config.FacebookAppId,
		ClientSecret: h.Config.FacebookAppSecret,
		RedirectURL:  redirectURL,
		Endpoint:     FacebookEndpoint,
		Scopes:       []string{"email", "public_profile"},
	}
}

func getUserInfoFromFacebook(token string) (FacebookUserDetails, error) {
	var fbUserDetails FacebookUserDetails
	req, err := http.NewRequest("GET", FacebookProfileURL+"?fields=id,name,email,picture&access_token="+token, nil)
	if err != nil {
		log.Error().Err(err).Msg("failed to create request")
		return FacebookUserDetails{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to get user info from facebook")
		return FacebookUserDetails{}, err
	}
	defer res.Body.Close()

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&fbUserDetails)
	if err != nil {
		log.Error().Err(err).Msg("failed to decode facebook user details")
		return FacebookUserDetails{}, err
	}

	return fbUserDetails, nil
}

// @BasePath /api
// Oauth2GoogleLogin godoc
// @Summary google login
// @Description google login
// @Tags authentication
// @Accept json
// @Produce json
// @Param Oauth2GoogleLoginRequest body Oauth2GoogleLoginRequest true "Oauth2 Google Login Request"
// @Success 200 {object} AuthenticationResponse
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/oauth2/google [post]
func (h *AuthenticationHandler) Oauth2GoogleLogin(ctx *gin.Context) {
	var req Oauth2GoogleLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("invalid request")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	tokenPayload, err := verifyGoogleToken(req.Token, h.Config.GoogleClientId)
	if err != nil {
		log.Error().Err(err).Msg("invalid token")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	id := tokenPayload.Subject
	email := tokenPayload.Claims["email"].(string)
	name := tokenPayload.Claims["name"].(string)

	authResponse, authenticatedUser, err := h.authenticate(id, oauthprovider.GOOGLE, name, email, ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to authenticate user")
		statusCode := http.StatusInternalServerError
		if err == exception.ErrLogin {
			statusCode = http.StatusUnauthorized
		}
		ctx.AbortWithStatusJSON(statusCode, exception.GetErrorResponse(err, statusCode))
		return
	}

	// Generate session-bound CSRF token and store in Redis
	csrfToken, err := csrf.GenerateAndStoreSessionToken(ctx, h.cacheService, h.Config, authenticatedUser.Uuid.String())
	if err != nil {
		log.Error().Err(err).Msg("failed to generate CSRF token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}
	// Set CSRF token in cookie
	csrf.SetCSRFCookie(ctx, csrfToken, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	})

	cookie.SetAuthCookies(ctx, cookie.CookieParams{
		Domain: h.Config.CookieDomain,
		Secure: h.Config.CookieSecure,
	}, cookie.AuthCookieParams{
		AccessToken:          authResponse.AccessToken,
		RefreshToken:         authResponse.RefreshToken,
		AccessTokenExpiresAt: authResponse.AccessTokenExpiresAt,
		IdToken:              authResponse.IdToken,
	})
	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) authenticate(id string, p oauthprovider.OauthProvider, name string, email string, ctx context.Context) (AuthenticationResponse, security.AuthenticatedUser, error) {
	var u user.UserEntity
	u, err := h.GetByOauthProvider(ctx, p, id)
	// Error is other than user not found
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Error().Err(err).Msg("failed to get user by oauth provider")
		// ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return AuthenticationResponse{}, security.AuthenticatedUser{}, exception.ErrLogin
	}

	if errors.Is(err, sql.ErrNoRows) {
		// User not found : create it
		u, err = h.CreateOauth(ctx, user.CreateOauthUserParams{
			Name:           name,
			Email:          email,
			Role:           role.USER,
			OauthProvider:  p,
			ExternalUserID: id,
		})

		if err != nil {
			log.Error().Err(err).Msg("failed to create oauth user")
			// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
			return AuthenticationResponse{}, security.AuthenticatedUser{}, err
		}
	}

	return h.createAuthenticationTokens(u, ctx)
}

func (h *AuthenticationHandler) createAuthenticationTokens(u user.UserEntity, ctx context.Context) (AuthenticationResponse, security.AuthenticatedUser, error) {
	authenticatedUser := user.ToAuthenticatedUser(u)

	t, err := h.generateTokens(authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate authentication tokens")
		// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return AuthenticationResponse{}, security.AuthenticatedUser{}, exception.ErrInternalServer
	}

	// Save the tokens in the database
	authReq := AuthenticationRequest{
		UserID:                u.ID,
		AccessToken:           t.AccessToken,
		RefreshToken:          t.RefreshToken,
		AccessTokenExpiresAt:  t.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
	}
	_, err = h.CreateAuthentication(ctx, authReq)
	if err != nil {
		log.Error().Err(err).Msg("failed to save authentication token")
		// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return AuthenticationResponse{}, security.AuthenticatedUser{}, exception.ErrInternalServer
	}

	authResponse := AuthenticationResponse{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		IdToken:              t.IdToken,
		AccessTokenExpiresAt: t.AccessTokenExpiresAt,
	}

	return authResponse, authenticatedUser, nil
}

// TODO encrypt SHA256 ?
func (h *AuthenticationHandler) generateTokens(authenticatedUser security.AuthenticatedUser) (authenticationToken, error) {
	now := time.Now().UTC()
	accessTokenAsString, accessTokenExpiresAt, err := generateToken(now, h.AccessTokenExpiresInAsSeconds)
	if err != nil {
		return authenticationToken{}, err
	}

	refreshTokenAsString, refreshTokenExpiresAt, err := generateToken(now, h.RefreshTokenExpiresInAsSeconds)
	if err != nil {
		return authenticationToken{}, err
	}

	idTokenKey, err := base64.StdEncoding.DecodeString(h.IdTokenKeyAsBase64)
	if err != nil {
		log.Error().Err(err).Msg("failed to decode id token key")
		return authenticationToken{}, err
	}
	idTokenAsString, _, err := generateIdToken(now, h.IdTokenExpiresInAsSeconds, idTokenKey, authenticatedUser)
	if err != nil {
		return authenticationToken{}, err
	}

	return authenticationToken{
		AccessToken:           accessTokenAsString,
		RefreshToken:          refreshTokenAsString,
		IdToken:               idTokenAsString,
		AccessTokenExpiresAt:  accessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}, nil
}
