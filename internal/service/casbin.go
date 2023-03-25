package service

import (
	"context"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/auth/jwt"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-oauth2/oauth2/v4/generates"
	"sso/internal/biz"
)

type CasbinService struct {
	enforcer *biz.Enforcer
}

func NewCasbinService(enforcer *biz.Enforcer) *CasbinService {
	return &CasbinService{enforcer: enforcer}
}

// 鉴权中间件
func (c *CasbinService) AuthorizeMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				if tr.Kind() == transport.KindHTTP {
					if token, ok := jwt.FromContext(ctx); ok {
						uid := token.(*generates.JWTAccessClaims).Id
						ok, err := c.enforcer.AuthorizeUserApiFromHttp(uid, tr.(http.Transporter).Request())
						if ok && err == nil {
							return handler(ctx, req)
						}
					}

				}
			}
			return nil, err
		}
	}
}
