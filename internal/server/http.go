package server

import (
	authv1 "sso/api/auth/v1"
	ssov1 "sso/api/sso/v1"
	"sso/internal/biz"
	"sso/internal/conf"
	"sso/internal/service"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/go-kratos/kratos/v2/transport/http"
)

// NewHTTPServer new a HTTP server.
func NewHTTPServer(c *conf.Server, auth *service.AuthService, sso *service.SSOService, enforcer *biz.Enforcer, logger log.Logger) *http.Server {
	var opts = []http.ServerOption{
		http.Middleware(
			recovery.Recovery(),
			logging.Server(logger),
		),
		// 鉴权
		http.Middleware(
			selector.Server(enforcer.AuthorizeMiddleware()).
				Prefix("sso").
				Build(),
		),
	}
	if c.Http.Network != "" {
		opts = append(opts, http.Network(c.Http.Network))
	}
	if c.Http.Addr != "" {
		opts = append(opts, http.Address(c.Http.Addr))
	}
	if c.Http.Timeout != nil {
		opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
	}
	srv := http.NewServer(opts...)

	r := srv.Route("/auth")
	r.GET("/code", auth.Authorize)
	r.GET("/token", auth.Token)

	authv1.RegisterAuthHTTPServer(srv, auth)
	ssov1.RegisterSSOHTTPServer(srv, sso)

	return srv
}
