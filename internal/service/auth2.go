package service

import (
	"context"
	"github.com/go-kratos/kratos/v2/transport/http"
	v1 "sso/api/auth/v1"
	"sso/internal/biz"
)

type AuthService struct {
	v1.UnimplementedAuthServer
	oauth2 *biz.Oauth2Server
}

func NewAuthService(oauth2 *biz.Oauth2Server) *AuthService {
	return &AuthService{oauth2: oauth2}
}

func (a *AuthService) Authorize(ctx http.Context) error {
	return a.oauth2.HandleAuthorizeRequestDefault(ctx.Response(), ctx.Request())
}

func (a *AuthService) Token(ctx http.Context) error {
	return a.oauth2.HandleTokenRequestDefault(ctx.Response(), ctx.Request())
}

func (a *AuthService) Verify(ctx context.Context, request *v1.VerifyRequest) (*v1.VerifyReply, error) {
	claims, err := a.oauth2.HandleTokenParse(ctx, request.VerifyBody.GetToken())
	return &v1.VerifyReply{
		ID:      claims.Id,
		Subject: claims.Subject,
	}, err
}
