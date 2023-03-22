package service

import (
	"context"

	pb "sso/api/sso/v1"
)

type SSOService struct {
	pb.UnimplementedSsoServer
}

func NewSSOService() *SSOService {
	return &SSOService{}
}

func (s *SSOService) UserList(ctx context.Context, req *pb.UserListRequest) (*pb.UserListReply, error) {
	return &pb.UserListReply{}, nil
}
