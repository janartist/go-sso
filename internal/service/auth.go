package service

import (
	"context"
	"sso/internal/biz"

	pb "sso/api/auth/v1"
)

type AuthService struct {
	pb.UnimplementedAuthServer

	enforcer *biz.Enforcer
	oauth2   *biz.Oauth2Server
}

func NewAuthService(enforcer *biz.Enforcer, oauth2 *biz.Oauth2Server) *AuthService {
	return &AuthService{enforcer: enforcer, oauth2: oauth2}
}

func (a *AuthService) GenToken(ctx context.Context, req *pb.GenTokenRequest) (*pb.GenTokenReply, error) {
	// a.oauth2.HandleTokenRequest(ctx, http.NewRequest("", "", nil))
	return &pb.GenTokenReply{ID: 1}, nil
}
func (a *AuthService) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyReply, error) {
	return &pb.VerifyReply{}, nil
}
