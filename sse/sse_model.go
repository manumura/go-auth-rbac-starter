package sse

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/rs/zerolog/log"
)

// New event messages are broadcast to all registered client connection channels
type Client struct {
	Channel chan string
	User    security.AuthenticatedUser
}

// https://github.com/gin-gonic/examples/blob/master/server-sent-event/main.go
// https://pascalallen.medium.com/streaming-server-sent-events-with-go-8cc1f615d561
// It keeps a list of clients those are currently attached
// and broadcasting events to those clients.
type EventStream struct {
	// Events are pushed to this channel by the main events-gathering routine
	Message chan string

	// New client connections
	NewClients chan Client

	// Closed client connections
	ClosedClients chan Client

	// Total client connections
	TotalClients map[Client]bool
}

// Initialize event and Start procnteessing requests
func NewEventStream() (event *EventStream) {
	event = &EventStream{
		Message:       make(chan string),
		NewClients:    make(chan Client),
		ClosedClients: make(chan Client),
		TotalClients:  make(map[Client]bool),
	}

	go event.listen()

	return
}

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func (stream *EventStream) listen() {
	for {
		select {
		// Add new available client
		case client := <-stream.NewClients:
			stream.TotalClients[client] = true
			log.Info().Msgf("Client added. %d registered clients", len(stream.TotalClients))

		// Remove closed client
		case client := <-stream.ClosedClients:
			delete(stream.TotalClients, client)
			close(client.Channel)
			log.Info().Msgf("Removed client. %d registered clients", len(stream.TotalClients))

		// Broadcast message to client
		case eventMsg := <-stream.Message:
			for clientMessageChan := range stream.TotalClients {
				clientMessageChan.Channel <- eventMsg
			}
		}
	}
}

func (stream *EventStream) ManageClients(clientChanKey string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// TODO remove test
		u, err := security.GetUserFromContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(err, http.StatusUnauthorized))
			return
		}
		fmt.Println("user", u)

		// Initialize client channel
		c := make(chan string)
		clientChannel := Client{
			Channel: c,
			User:    u,
		}

		// Send new connection to event server
		stream.NewClients <- clientChannel

		defer func() {
			// Drain client channel so that it does not block. Server may keep sending messages to this channel
			go func() {
				for range clientChannel.Channel {
				}
			}()
			// Send closed connection to event server
			stream.ClosedClients <- clientChannel
		}()

		ctx.Set(clientChanKey, clientChannel)

		ctx.Next()
	}
}
