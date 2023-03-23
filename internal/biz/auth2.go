package biz

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"

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
	ID     uint64 `gorm:"type:varchar(20);primarykey"`
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
	manager.MapTokenStorage(oredis.NewRedisStoreWithCli(redisClient))
	// client 存储
	manager.MapClientStorage(clientStore)
	//token算法
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	//密码 code 生成token规则
	manager.SetPasswordTokenCfg(&manage.Config{AccessTokenExp: 2 * time.Hour, IsGenerateRefresh: false})
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{AccessTokenExp: 2 * time.Hour, RefreshTokenExp: time.Hour, IsGenerateRefresh: true})
	manager.SetRefreshTokenCfg(&manage.RefreshingConfig{
		AccessTokenExp:  2 * time.Hour,
		RefreshTokenExp: time.Hour,
	})

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetAllowedGrantType(oauth2.AuthorizationCode, oauth2.PasswordCredentials, oauth2.Refreshing)
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Error("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		re.ErrorCode = 401
		log.Error("Response Error:", re.Error.Error(), re.Description)
	})
	// 不同客户端不同授权模式
	srv.SetClientAuthorizedHandler(func(clientID string, grant oauth2.GrantType) (allowed bool, err error) {
		allowed = true
		return
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})
	//
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		return "11s", nil
	})
	// 通过账号密码返回用户ID
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

// HandleAuthorizeRequest code request handling
func (o *Oauth2Server) HandleAuthorizeRequestDefault(w http.ResponseWriter, r *http.Request) error {
	return o.server.HandleAuthorizeRequest(w, r)
}

// HandleTokenRequest token request handling
func (o *Oauth2Server) HandleTokenRequestDefault(w http.ResponseWriter, r *http.Request) error {
	return o.server.HandleTokenRequest(w, r)
}

// token parse handling
func (o *Oauth2Server) HandleTokenParse(access string) (*generates.JWTAccessClaims, error) {
	// Parse and verify jwt access token
	token, err := jwt.ParseWithClaims(access, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte("00000000"), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
