package user

import (
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/message"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/manumura/go-auth-rbac-starter/sse"
	"github.com/rs/zerolog/log"
)

const (
	UserEventsClientChanContextKey = "userEventsClientChan"
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

// @BasePath /api
// CreateUser godoc
// @Summary create new user
// @Description create new user
// @Tags user
// @Accept json
// @Produce json
// @Param CreateUserRequest body CreateUserRequest true "Create User Request"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} User
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/users [post]
func (h *UserHandler) CreateUser(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	var req CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	if err := h.Validate.Struct(req); err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	isEmailExist, err := h.IsEmailExist(ctx, req.Email, uuid.Nil)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}
	if isEmailExist {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
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
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	u := ToUser(user)

	// Send email with generated password
	go h.EmailService.SendTemporaryPasswordEmail(user.UserCredentials.Email, "", generatedPassword)

	// Push new user event
	e := NewUserChangeEvent(CREATED, u, authenticatedUser.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, u)
}

// @BasePath /api
// GetAllUsers godoc
// @Summary get all users
// @Description get all users
// @Tags user
// @Accept json
// @Produce json
// @Param role query string false "Role"
// @Param page query string false "Page"
// @Param pageSize query string false "Page size"
// @Param Authorization header string true "Bearer token"
// @Success 200 {array} User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/users [get]
func (h *UserHandler) GetAllUsers(ctx *gin.Context) {
	r := role.Role(ctx.Query("role"))

	page := 1
	if ctx.Query("page") != "" {
		p, err := strconv.Atoi(ctx.Query("page"))
		if err != nil {
			log.Warn().Err(err).Msg("page is not a number: defaulting to 1")
			page = 1
		} else {
			page = p
		}
	}

	pageSize := 10
	if ctx.Query("pageSize") != "" {
		ps, err := strconv.Atoi(ctx.Query("pageSize"))
		if err != nil {
			log.Warn().Err(err).Msg("pageSize is not a number: defaulting to 10")
			pageSize = 10
		} else {
			pageSize = ps
		}
	}

	req := GetUsersRequest{
		Role:     r,
		Page:     page,
		PageSize: pageSize,
	}

	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	offset := (page - 1) * pageSize
	p := GetUsersParams{
		Limit:  pageSize,
		Offset: offset,
	}
	if r != "" {
		p.Role = &r
	}

	u, err := h.GetAll(ctx, p)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	cp := CountUsersParams{}
	if r != "" {
		cp.Role = &r
	}
	c, err := h.CountAll(ctx, cp)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	users := ToUsers(u)
	pageResponse := common.Page[User]{
		Elements:      users,
		TotalElements: c,
	}
	ctx.JSON(http.StatusOK, pageResponse)
}

// TODO handle multiple providers
// @BasePath /api
// GetUser godoc
// @Summary get user by uuid
// @Description get user by uuid
// @Tags user
// @Accept json
// @Produce json
// @Param uuid path string true "User UUID"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/users/{uuid} [get]
func (h *UserHandler) GetUser(ctx *gin.Context) {
	userUuidAsString := ctx.Param("uuid")
	log.Info().Msgf("get user by uuid: %s", userUuidAsString)

	_, err := uuid.Parse(userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	user := ToUser(u)
	ctx.JSON(http.StatusOK, user)
}

// @BasePath /api
// UpdateUser godoc
// @Summary update user by uuid
// @Description update user by uuid
// @Tags user
// @Accept json
// @Produce json
// @Param UpdateUserRequest body UpdateUserRequest true "Update User Request"
// @Param uuid path string true "User UUID"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} User
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/users/{uuid} [put]
func (h *UserHandler) UpdateUser(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	userUuidAsString := ctx.Param("uuid")
	log.Info().Msgf("update user by uuid %s", userUuidAsString)

	userUUID, err := uuid.Parse(userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	var req UpdateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err = h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	if req.Email != nil {
		isEmailExist, err := h.IsEmailExist(ctx, *req.Email, userUUID)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
			return
		}
		if isEmailExist {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidEmail, http.StatusBadRequest))
			return
		}
	}

	_, err = h.UpdateByUUID(ctx, userUuidAsString, UpdateUserParams(req))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	u, err := h.GetByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	user := ToUser(u)

	// Push new user event
	e := NewUserChangeEvent(UPDATED, user, authenticatedUser.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, user)
}

// @BasePath /api
// DeleteUser godoc
// @Summary delete user by uuid
// @Description delete user by uuid
// @Tags user
// @Accept json
// @Produce json
// @Param uuid path string true "User UUID"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} User
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/users/{uuid} [delete]
func (h *UserHandler) DeleteUser(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	userUuidAsString := ctx.Param("uuid")
	log.Info().Msgf("delete user by uuid %s", userUuidAsString)

	_, err = uuid.Parse(userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	err = h.DeleteByUUID(ctx, userUuidAsString)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	user := ToUser(u)

	// Push new user event
	e := NewUserChangeEvent(DELETED, user, authenticatedUser.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, user)
}

// @BasePath /api
// StreamUserEvents godoc
// @Summary stream user events
// @Description stream user events
// @Tags user
// @Produce text/event-stream
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} sse.Event
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/events/users [get]
func (h *UserHandler) StreamUserEvents(ctx *gin.Context) {
	v, ok := ctx.Get(UserEventsClientChanContextKey)
	if !ok {
		log.Error().Msg("client channel not found")
		return
	}

	client, ok := v.(sse.Client[UserChangeEvent])
	if !ok {
		log.Error().Msg("client channel is not of type Client[UserChangeEvent]")
		return
	}

	ctx.Stream(func(w io.Writer) bool {
		// Stream message to client from message channel
		if event, ok := <-client.Channel; ok {
			// ctx.SSEvent("event", event)
			sse.RenderSSEvent(ctx, event.Type.String(), event.ID, event.Data)
			return true
		}
		return false
	})
}
