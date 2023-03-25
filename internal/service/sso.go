package service

import (
	"context"
	"fmt"
	"sso/internal/biz"

	pb "sso/api/sso/v1"
)

type SSOService struct {
	pb.UnimplementedSsoServer
	enforcer *biz.Enforcer
}

func NewSSOService(enforcer *biz.Enforcer) *SSOService {
	return &SSOService{enforcer: enforcer}
}

func (s *SSOService) UserList(ctx context.Context, req *pb.UserListRequest) (*pb.UserListReply, error) {
	s.enforcer.AddRoleForUserWithPrefix("2", "2")
	s.enforcer.AddRoleForUserWithPrefix("3", "2")
	s.enforcer.AddPermissionForRoleWithPrefix("2", biz.CasbinObjTypeApi, "/ss:get", "client_1")
	s.enforcer.DeletePermissionForRoleWithPrefix("2", biz.CasbinObjTypeApi, "/ss:get", "client_1")
	s.enforcer.AddPermissionForUserWithPrefix("2", biz.CasbinObjTypeApi, "/ss2:get", "client_2")
	s.enforcer.AddPermissionForRoleWithPrefix("2", biz.CasbinObjTypeApi, "/ss2:get", "client_2")
	res, err := s.enforcer.Authorize("user_4", biz.CasbinObjTypeApi, "/ss2:get", "client_2", "1")
	res2, err2 := s.enforcer.Authorize("user_1", biz.CasbinObjTypeApi, "/ss2:get", "client_2", "2")
	fmt.Print(res, err, "\n", res2, err2, "\n")
	return &pb.UserListReply{}, nil
}
