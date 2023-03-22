package biz

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http"
	"gorm.io/gorm"
	v1 "sso/api/casbin/v1"
	"sso/internal/conf"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/util"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

type Casbin struct {
	db    *gorm.DB
	c     *conf.Casbin
	model *model.Model
}

func NewCasbinFromGorm(db *gorm.DB, model *model.Model, c *conf.Casbin) *Casbin {
	return &Casbin{db, c, model}
}

type Enforcer struct {
	*casbin.Enforcer
	casbin *Casbin
}

// NewEnforcer
func NewEnforcer(c *Casbin) (*Enforcer, error) {
	// Initialize  casbin adapter
	adapter, err := gormadapter.NewAdapterByDBUseTableName(c.db, c.c.GetGorm().GetPrefix(), c.c.GetGorm().GetTable())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize casbin adapter: %v", err)
	}

	// Load model configuration file and policy store adapter
	enforcer, err := casbin.NewEnforcer(*c.model, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %v", err)
	}
	return &Enforcer{enforcer, c}, nil
}

// Authorize casbin 统一鉴权
// Authorize determines if current user has been authorized to take an action on an object.
func (enforcer *Enforcer) AuthorizeFromHttp(r *http.Request) (bool, error) {
	// Extract client IP address from request headers
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	var (
		uid    = ""
		apiID  = ""
		tenant = ""
	)

	// Load policy from Database
	err := enforcer.LoadPolicy()
	if err != nil {
		return false, v1.ErrorContentMissing("LoadPolicy error")
	}

	// Casbin enforces policy
	ok, err := enforcer.Enforce(
		enforcer.casbin.c.GetGorm().GetUserPrefix()+uid,
		enforcer.casbin.c.GetGorm().GetApiPrefix()+apiID,
		tenant,
		clientIP,
	)
	if err != nil || !ok {
		return false, v1.ErrorAuthError("Enforce error")
	}
	return true, nil
}

// 鉴权中间件
func (enforcer *Enforcer) AuthorizeMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				if tr.Kind() == transport.KindHTTP {
					ok, err = enforcer.AuthorizeFromHttp(tr.(http.Transporter).Request())
					if !ok || err != nil {
						return nil, err
					}
				}
			}
			return handler(ctx, req)
		}
	}
}

// AddUserForRoleInDomain 添加用户
func (enforcer *Enforcer) AddUserForRoleInDomain(user, role, domain string) (bool, error) {
	if enforcer.GetModel().HasPolicy("g", "g", []string{user, role, domain}) {
		return true, nil
	}
	return enforcer.AddNamedGroupingPolicy("g", user, role, domain)
}

// DelUserForRoleInDomain 添加角色
func (enforcer *Enforcer) DelUserForRoleInDomain(user, role, domain string) (bool, error) {
	if enforcer.GetModel().HasPolicy("g", "g", []string{user, role, domain}) {
		return enforcer.RemoveNamedGroupingPolicy("g", user, role, domain)
	}
	return true, nil
}

// GetUsersForRoleInDomain 从角色查询用户
func (enforcer *Enforcer) GetUsersForRoleInDomain(role, domain string) ([]string, error) {
	res, err := enforcer.GetModel()["g"]["g"].RM.GetUsers(role, domain)
	return res, err
}

// GetRolesForUserInDomain 从用户查询角色
func (enforcer *Enforcer) GetRolesForUserInDomain(user, domain string) ([]string, error) {
	res, err := enforcer.GetModel()["g"]["g"].RM.GetRoles(user, domain)
	return res, err
}

// AddApiForMenuInDomain 从菜单添加api
func (enforcer *Enforcer) AddApiForMenuInDomain(api, menu, domain string) (bool, error) {
	if enforcer.GetModel().HasPolicy("g", "g2", []string{api, menu, domain}) {
		return true, nil
	}
	return enforcer.AddNamedGroupingPolicy("g2", api, menu, domain)
}

// DelApiForMenuInDomain 从菜单删除api
func (enforcer *Enforcer) DelApiForMenuInDomain(api, menu, domain string) (bool, error) {
	if enforcer.GetModel().HasPolicy("g", "g2", []string{api, menu, domain}) {
		return enforcer.RemoveNamedGroupingPolicy("g2", api, menu, domain)
	}
	return true, nil
}

// GetApisForMenuInDomain 获取菜单下的api
func (enforcer *Enforcer) GetApisForMenuInDomain(menu, domain string) ([]string, error) {
	res, err := enforcer.GetModel()["g"]["g2"].RM.GetUsers(menu, domain)
	return res, err
}

// BWIpMatch 支持黑白名单的ip验证
//ipMatch("192.168.2.1", "192.168.2.0/24", true)
func (c *Casbin) BWIpMatch(args ...interface{}) (interface{}, error) {
	rIp := args[0].(string)
	ok := false
	var ips []string
	black := false
	//黑名单
	if black {
		for _, ip := range ips {
			ok = util.IPMatch(rIp, ip)
			if ok {
				return false, nil
			}
		}
		return true, nil
	}
	//白名单
	for _, ip := range ips {
		ok = util.IPMatch(rIp, ip)
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func RABCModelWithIpMatch() *model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, dom, ip")
	m.AddDef("p", "p", "sub, obj, dom")
	m.AddDef("g", "g", "_, _, _")
	m.AddDef("g", "g2", "_, _, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub, r.dom) && g2(r.obj, p.obj, r.dom) && r.dom == p.dom && BWIpMatch(r.ip) || r.sub == \"1\"")
	return &m
}
