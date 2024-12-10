package user

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/pb"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/rs/zerolog/log"
)

// user events channel
var UserEventsChannel = make(chan *pb.Event)

type UserHandler struct {
	// https://stackoverflow.com/questions/28014591/nameless-fields-in-go-structs
	UserService
	*validator.Validate
}

func NewUserHandler(service UserService, validate *validator.Validate) UserHandler {
	return UserHandler{
		service,
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

	// TODO send event to user event channel
	// UserEventsChannel <- &pb.Event{
	// 	Id:   fmt.Sprintf("Event %d", 1),
	// 	Type: fmt.Sprintf("Event %d type", 1),
	// 	Data: fmt.Sprintf("Event %d data", 1),
	// }

	// TODO email
	// Send email with link to verify email
	// this.logger.verbose(`[EMAIL][REGISTER] Sending email to: ${email}`);
	// this.emailService
	//   .sendRegistrationEmail(email, 'en', verifyEmailToken)
	//   .then((result) => {
	//     this.logger.verbose(`[EMAIL][REGISTER] Result Sending email: ${JSON.stringify(result)}`);
	//   })
	//   .catch((err) => this.logger.error(err));

	// Send new user email to root user
	// const rootUserEmail = appConfig.ROOT_ACCOUNT_EMAIL;
	// this.logger.verbose(`[EMAIL][NEW_USER] Sending email to: ${rootUserEmail}`);
	// this.emailService
	//   .sendNewUserEmail(rootUserEmail, 'en', email)
	//   .then((result) => {
	//     this.logger.verbose(`[EMAIL][NEW_USER] Result Sending email: ${JSON.stringify(result)}`);
	//   })
	//   .catch((err) => this.logger.error(err));

	ctx.JSON(http.StatusOK, authenticatedUser)
}

// TODO query params
func (h *UserHandler) GetAllUsers(ctx *gin.Context) {
	u, err := h.GetAll(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	authenticatedUsers := ToAuthenticatedUsers(u)
	ctx.JSON(http.StatusOK, authenticatedUsers)
}
