package biz

import (
	"context"
	"github.com/go-kratos/kratos/v2/log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username  string    `json:"username" gorm:"type:varchar(50);unique;not null;comment:用户名"`
	Mobile    string    `json:"mobile" gorm:"type:varchar(20);unique;null;comment:手机"`
	Password  string    `json:"-" gorm:"type:varchar(100);comment:密码"`
	LastLogin time.Time `json:"last_login" gorm:"comment:上次登录时间"`
	Status    int       `json:"status" gorm:"type:tinyint(1);default 0;comment:状态：0正常，1黑名单"`
}

type Tenant struct {
	ID     string `gorm:"type:varchar(20);primarykey"`
	Secret string `gorm:"type:varchar(50);not null"`
	Domain string `gorm:"type:varchar(50);not null"`
	UserID string `gorm:"type:varchar(20);not null"`
}

type AuthRepo interface {
	Auth(ctx context.Context, user *User, clientID, username, password string) error
}

type Oauth2Server struct {
	auth   AuthRepo
	server *server.Server

	log *log.Helper
}

func NewOauth2Server(redisClient *redis.Client, clientStore oauth2.ClientStore, auth AuthRepo, logger log.Logger) *Oauth2Server {
	manager := manage.NewDefaultManager()
	// token 存储
	manager.MustTokenStorage(oredis.NewRedisStoreWithCli(redisClient), nil)
	// client 存储
	manager.MapClientStorage(clientStore)
	//token算法
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	//密码生成token规则
	manager.SetPasswordTokenCfg(&manage.Config{AccessTokenExp: 2 * time.Hour, IsGenerateRefresh: false})

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientBasicHandler)
	srv.SetAllowedGrantType(oauth2.PasswordCredentials)
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Error("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		re.ErrorCode = 401
		log.Error("Response Error:", re.Error.Error(), re.Description)
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})
	//通过账号密码返回用户ID
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		var user User
		err := auth.Auth(ctx, &user, clientID, username, password)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(int(user.ID)), nil
	})
	return &Oauth2Server{
		auth:   auth,
		server: srv,
		log:    log.NewHelper(logger),
	}
}

// HandleTokenRequest token request handling
func (o *Oauth2Server) HandleTokenRequest(ctx context.Context, request *http.Request) (map[string]interface{}, error) {
	gt, tgr, err := o.server.ValidationTokenRequest(request)
	if err != nil {
		_, _, _ = o.server.GetErrorData(err)
		return nil, err
	}

	ti, err := o.server.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		_, _, _ = o.server.GetErrorData(err)
		return nil, nil
	}
	return o.server.GetTokenData(ti), nil
}
