package gapi

import (
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/pb"
)

type GrpcServer struct {
	pb.UnimplementedUserEventServer
	config config.Config
}

func NewGrpcServer(config config.Config) (*GrpcServer, error) {
	server := &GrpcServer{
		config: config,
	}

	return server, nil
}
