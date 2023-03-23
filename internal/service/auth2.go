package service

import (
	"context"
	"fmt"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/auth/jwt"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-oauth2/oauth2/v4/generates"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	v1 "sso/api/auth/v1"
	"sso/internal/biz"
)

type AuthService struct {
	v1.UnimplementedAuthServer
	oauth2   *biz.Oauth2Server
	enforcer *biz.Enforcer
}

func NewAuthService(oauth2 *biz.Oauth2Server,
	enforcer *biz.Enforcer) *AuthService {
	return &AuthService{oauth2: oauth2, enforcer: enforcer}
}

// code认证
func (a *AuthService) Authorize(ctx http.Context) error {
	return a.oauth2.HandleAuthorizeRequestDefault(ctx.Response(), ctx.Request())
}

// token生成
func (a *AuthService) Token(ctx http.Context) error {
	return a.oauth2.HandleTokenRequestDefault(ctx.Response(), ctx.Request())
}

// token验证
func (a *AuthService) Verify(ctx context.Context, request *v1.VerifyRequest) (*v1.VerifyReply, error) {
	var (
		ok     bool
		err    error
		claims *generates.JWTAccessClaims
	)

	_, errs := middleware.Chain(a.JwtServerMiddleware(request.GetVerifyBody().GetAccessToken()))(func(ctx context.Context, req interface{}) (interface{}, error) {
		if token, ok2 := jwt.FromContext(ctx); ok2 {
			claims = token.(*generates.JWTAccessClaims)
			ok, err = a.enforcer.Authorize(
				claims.Id,
				request.GetVerifyBody().GetApiUrl(),
				request.GetVerifyBody().GetTenant(),
				request.GetVerifyBody().GetClientIp(),
			)
			return nil, err
		}
		return nil, nil
	})(ctx, request)
	if errs != nil {
		return nil, err
	}

	return &v1.VerifyReply{
		Access: ok,
		User: &v1.VerifyReply_User{
			ID:      claims.Id,
			Subject: claims.Subject,
		},
	}, err
}

// access_token中间件
func (a *AuthService) TokenMiddleware() middleware.Middleware {
	return a.JwtServerMiddleware("")
}

// access_token中间件
func (a *AuthService) JwtServerMiddleware(tokenWithBearer string) middleware.Middleware {
	return jwt.Server(func(t *jwtv4.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv4.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte("00000000"), nil
	}, jwt.WithClaims(func() jwtv4.Claims {
		return &generates.JWTAccessClaims{}
	}),
		jwt.WithTokenHeader(map[string]interface{}{"Authorization": tokenWithBearer}),
	)
}
