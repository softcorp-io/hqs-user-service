package mock

import (
	"fmt"
	"log"
	"net"
	"sync"

	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"

	"google.golang.org/grpc"
)

// RunServer - runs the hqs-user microservice
func RunServer(wg *sync.WaitGroup) {
	// create the service and run the service
	lis, err := net.Listen("tcp", ":9091")
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to listen with err %v", err))
	}

	log.Printf("Service running on port: %s", "9091")

	// setup grpc

	grpcServer := grpc.NewServer()

	handler, err := NewHandler()
	if err != nil {
		TearDownMongoDocker()
		log.Fatal(fmt.Sprintf("Failed to get handler with err %v", err))
	}
	wg.Done()
	// register handler
	proto.RegisterUserServiceServer(grpcServer, handler)
	// run the server
	if err := grpcServer.Serve(lis); err != nil {
		TearDownMongoDocker()
		log.Fatal(fmt.Sprintf("Failed to serve with err %v", err))
	}
}
