package service

import (
	"context"
	"fmt"

	pb "sso/api/sso/v1"
	"sso/internal/biz"
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
	s.enforcer.AddObjPermissionForRoleWithPrefix("2", biz.CasbinObjTypeApi, "/ss/:id", "(GET)|(POST)", "client_1")
	s.enforcer.AddObjPermissionForRoleWithPrefix("2", biz.CasbinObjTypeApi, "/ss", "post", "client_1")
	s.enforcer.AddObjPermissionForRoleWithPrefix("2", biz.CasbinObjTypeMenu, "wode", "read", "client_2")
	res, err := s.enforcer.Authorize("user_3", biz.CasbinObjTypeApi, "/ss/1", "GET", "client_1", "1")
	res2, err2 := s.enforcer.Authorize("user_2", biz.CasbinObjTypeMenu, "wode", "read", "client_2", "2")
	fmt.Print(res, err, "\n", res2, err2, "\n")
	return &pb.UserListReply{}, nil
}
