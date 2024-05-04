package user

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/pb"
)

// user events channel
var UserEventsChannel = make(chan *pb.Event)

type UserHandler struct {
	// https://stackoverflow.com/questions/28014591/nameless-fields-in-go-structs
	// service service.UserService
	// service.UserService
}

// func NewUserHandler(service *service.UserService) *UserHandler {
func NewUserHandler() *UserHandler {
	return &UserHandler{
		// service: *service,
		// *service,
	}
}

func (h *UserHandler) Register(ctx *gin.Context) {
	UserEventsChannel <- &pb.Event{
		Id:   fmt.Sprintf("Event %d", 1),
		Type: fmt.Sprintf("Event %d type", 1),
		Data: fmt.Sprintf("Event %d data", 1),
	}
	ctx.JSON(http.StatusOK, "register called")
}
