package main


import (
	"log"
	"net"


	"github.com/TykTechnologies/tyk/coprocess"
	"google.golang.org/grpc"
)

const (
	ListenAddress   = ":5555"
)

func main() {
	lis, err := net.Listen("tcp", ListenAddress)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	initialise()

	log.Printf("starting grpc server on %v", ListenAddress)
	s := grpc.NewServer()
	coprocess.RegisterDispatcherServer(s, &Dispatcher{})
	if err := s.Serve(lis); err != nil{
		panic(err)
	}
}
