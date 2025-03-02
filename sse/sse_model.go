package sse

import (
	"net/http"

	"github.com/gin-contrib/sse"
	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/rs/zerolog/log"
)

// New event messages are broadcast to all registered client connection channels
type Client[T any] struct {
	Channel chan T
	User    security.AuthenticatedUser
}

// https://github.com/gin-gonic/examples/blob/master/server-sent-event/main.go
// https://pascalallen.medium.com/streaming-server-sent-events-with-go-8cc1f615d561
// It keeps a list of clients those are currently attached
// and broadcasting events to those clients.
type EventStream[T any] struct {
	// Events are pushed to this channel by the main events-gathering routine
	Message chan T

	// New client connections
	NewClients chan Client[T]

	// Closed client connections
	ClosedClients chan Client[T]

	// Total client connections
	TotalClients map[Client[T]]bool
}

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func (stream *EventStream[T]) Listen() {
	for {
		select {
		// Add new available client
		case client := <-stream.NewClients:
			stream.TotalClients[client] = true
			log.Info().Msgf("===== Client added. %d registered clients =====", len(stream.TotalClients))

		// Remove closed client
		case client := <-stream.ClosedClients:
			delete(stream.TotalClients, client)
			close(client.Channel)
			log.Info().Msgf("===== Removed client. %d registered clients =====", len(stream.TotalClients))

		// Broadcast message to client
		case eventMsg := <-stream.Message:
			for client, _ := range stream.TotalClients {
				client.Channel <- eventMsg
			}
		}
	}
}

func (stream *EventStream[T]) ManageClientsMiddleware(clientChanKey string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authenticatedUser, err := security.GetUserFromContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(err, http.StatusUnauthorized))
			return
		}

		// Initialize client channel
		c := make(chan T)
		client := Client[T]{
			Channel: c,
			User:    authenticatedUser,
		}

		// Add client to event server
		stream.NewClients <- client

		defer func() {
			go func() {
				for range client.Channel {
					// Drain client channel so that it does not block. Server may keep sending messages to this channel
				}
			}()

			// Send closed connection to event server
			log.Info().Msgf("===== Closing client connection for client: %s =====", authenticatedUser.Uuid)
			stream.ClosedClients <- client
		}()

		ctx.Set(clientChanKey, client)

		ctx.Next()
	}
}

func RenderSSEvent(ctx *gin.Context, event string, id string, message interface{}) {
	ctx.Render(-1, sse.Event{
		Event: event,
		Id:    id,
		// Retry: retry,
		Data: message,
	})
}
