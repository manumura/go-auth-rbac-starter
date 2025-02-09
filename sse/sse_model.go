package sse

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/rs/zerolog/log"
)

// New event messages are broadcast to all registered client connection channels
type ClientChan chan string

// https://github.com/gin-gonic/examples/blob/master/server-sent-event/main.go
// https://pascalallen.medium.com/streaming-server-sent-events-with-go-8cc1f615d561
// It keeps a list of clients those are currently attached
// and broadcasting events to those clients.
type EventStream struct {
	// Events are pushed to this channel by the main events-gathering routine
	Message ClientChan

	// New client connections
	NewClients chan ClientChan

	// Closed client connections
	ClosedClients chan ClientChan

	// Total client connections
	TotalClients map[ClientChan]bool
}

// Initialize event and Start procnteessing requests
func NewEventStream() (event *EventStream) {
	event = &EventStream{
		Message:       make(ClientChan),
		NewClients:    make(chan ClientChan),
		ClosedClients: make(chan ClientChan),
		TotalClients:  make(map[ClientChan]bool),
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
			close(client)
			log.Info().Msgf("Removed client. %d registered clients", len(stream.TotalClients))

		// Broadcast message to client
		case eventMsg := <-stream.Message:
			for clientMessageChan := range stream.TotalClients {
				clientMessageChan <- eventMsg
			}
		}
	}
}

func (stream *EventStream) ManageClients(clientChanKey string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// TODO remove test
		val, exists := ctx.Get(common.AuthenticatedUserContextKey)
		if exists {
			fmt.Println("User found in context", val)
		}

		// Initialize client channel
		clientChan := make(ClientChan)

		// Send new connection to event server
		stream.NewClients <- clientChan

		defer func() {
			// Drain client channel so that it does not block. Server may keep sending messages to this channel
			go func() {
				for range clientChan {
				}
			}()
			// Send closed connection to event server
			stream.ClosedClients <- clientChan
		}()

		ctx.Set(clientChanKey, clientChan)

		ctx.Next()
	}
}
