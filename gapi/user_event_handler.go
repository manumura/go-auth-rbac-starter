package gapi

import (
	"fmt"

	"github.com/manumura/go-auth-rbac-starter/pb"
	"github.com/manumura/go-auth-rbac-starter/user"
)

// TODO UserChangeEvent
func (s *GrpcServer) GetUserEvents(req *pb.UserEventsRequest, stream pb.UserEvent_GetUserEventsServer) error {

	fmt.Println("GetUserEvents called")

	for {
		event := <-user.UserEventsChannel
		fmt.Printf("event : %v\n", event)

		resp := pb.UserEventsResponse{
			Event: event,
		}

		if err := stream.Send(&resp); err != nil {
			fmt.Printf("send error %v", err)
		}
	}

	// var wg sync.WaitGroup
	// for i := 0; i < 5; i++ {
	// 	wg.Add(1)
	// 	go func(count int) {
	// 		defer wg.Done()
	// 		time.Sleep(time.Duration(count) * time.Second)
	// 		event := pb.Event{
	// 			Id:   fmt.Sprintf("Event %d", count),
	// 			Type: fmt.Sprintf("Event %d type", count),
	// 			Data: fmt.Sprintf("Event %d data", count),
	// 		}

	// 		resp := pb.UserEventsResponse{
	// 			Event: &event,
	// 		}

	// 		if err := stream.Send(&resp); err != nil {
	// 			fmt.Printf("send error %v", err)
	// 		}
	// 		fmt.Printf("finishing request number : %d\n", count)
	// 	}(i)
	// }

	// wg.Wait()
	// return nil
}
