package user

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/pb"
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

var index = 1
var Users = []User{}

func (h *UserHandler) Register(ctx *gin.Context) {
	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest))
		return
	}

	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err))
		return
	}

	user, err := h.Create(ctx, CreateUserRequest{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Role:     USER,
	})

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err))
		return
	}

	Users = append(Users, user)
	index++

	fmt.Printf("Register called %v\n", Users)

	userResponse := ToUserResponse(user)

	// TODO send event to user event channel
	// UserEventsChannel <- &pb.Event{
	// 	Id:   fmt.Sprintf("Event %d", 1),
	// 	Type: fmt.Sprintf("Event %d type", 1),
	// 	Data: fmt.Sprintf("Event %d data", 1),
	// }

	ctx.JSON(http.StatusOK, userResponse)
}
