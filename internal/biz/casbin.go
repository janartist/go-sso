package biz

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http"
	"gorm.io/gorm"
	v1 "sso/api/casbin/v1"
	"sso/internal/conf"
)

type Casbin struct {
	db      *gorm.DB
	c       *conf.Casbin
	model   model.Model
	watcher persist.WatcherEx
}

func NewCasbinFromGorm(db *gorm.DB, model model.Model, watcher persist.WatcherEx, c *conf.Casbin) *Casbin {
	return &Casbin{db, c, model, watcher}
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
	enforcer, err := casbin.NewEnforcer(c.model, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %v", err)
	}
	enforcer.AddFunction("BWIpMatch", c.BWIpMatch)
	enforcer.SetWatcher(c.watcher)
	return &Enforcer{enforcer, c}, nil
}

// Authorize casbin 统一鉴权
// Authorize determines if current user has been authorized to take an action on an apiect.
func (enforcer *Enforcer) Authorize(uid, apiID, tenant, clientIP string) (bool, error) {
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
func (enforcer *Enforcer) AuthorizeFromHttp(r *http.Request) (bool, error) {
	//enforcer.AddUserForRoleInDomain("1", "1", "22")
	//enforcer.AddApiForMenuInDomain("2", "2", "22")
	// Extract client IP address from request headers
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	var (
		uid    = "1"
		apiID  = "2"
		tenant = "3"
	)
	return enforcer.Authorize(uid, apiID, tenant, clientIP)
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

//  添加用户
func (enforcer *Enforcer) BindUserRole(user, role string) (bool, error) {
	return enforcer.AddNamedGroupingPolicy("g", user, role)
}

//  删除用户
func (enforcer *Enforcer) DelUserRole(user, role string) (bool, error) {
	return enforcer.RemoveNamedGroupingPolicy("g", user, role)
}

// GetUsersForRoleInDomain 从角色查询用户
func (enforcer *Enforcer) GetUsersInRole(role string) ([]string, error) {
	res, err := enforcer.GetNamedRoleManager("g").GetUsers(role)
	return res, err
}

// GetRolesForUserInDomain 从用户查询角色
func (enforcer *Enforcer) GetRolesInUser(user string) ([]string, error) {
	res, err := enforcer.GetNamedRoleManager("g").GetRoles(user)
	return res, err
}

// AddApiForMenuInDomain 从菜单添加api
func (enforcer *Enforcer) BindApiMenuInDomain(api, menu, domain string) (bool, error) {
	return enforcer.AddNamedGroupingPolicy("g2", api, menu, domain)
}

// DelApiForMenuInDomain 从菜单删除api
func (enforcer *Enforcer) DelApiMenuInDomain(api, menu, domain string) (bool, error) {
	return enforcer.RemoveNamedGroupingPolicy("g2", api, menu, domain)
}

// GetApisForMenuInDomain 获取菜单下的api
func (enforcer *Enforcer) GetApisInMenuDomain(menu, domain string) ([]string, error) {
	res, err := enforcer.GetNamedRoleManager("g2").GetUsers(menu, domain)
	return res, err
}

// GetApisForMenuInDomain 获取api下的菜单
func (enforcer *Enforcer) GetMenusInApiDomain(api, domain string) ([]string, error) {
	res, err := enforcer.GetNamedRoleManager("g2").GetRoles(api, domain)
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

// g为user->role的group
// g2为api->menu的group
func RABCModelWithIpMatch() model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "user, api, tenant, ip") // 权限检验入参
	m.AddDef("p", "p", "user, api, tenant")     // 权限验参
	m.AddDef("g", "g", "_, _, _")               // g的参数为user,role
	m.AddDef("g", "g2", "_, _, _")              // g的参数为api,menu,dom
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.user, p.user, r.tenant) && g2(r.api, p.api, r.tenant) && r.tenant == p.tenant && BWIpMatch(r.ip) || r.user == \"1\"")
	return m
}

func NewCasbinWatcherEx() *CasbinWatcherEx {
	return &CasbinWatcherEx{}
}

type CasbinWatcherEx struct {
	callback func(string)
}

func (w *CasbinWatcherEx) Close() {
}

func (w *CasbinWatcherEx) SetUpdateCallback(callback func(string)) error {
	w.callback = callback
	return nil
}

func (w *CasbinWatcherEx) Update() error {
	if w.callback != nil {
		w.callback("")
	}
	return nil
}

func (w CasbinWatcherEx) UpdateForAddPolicy(sec, ptype string, params ...string) error {
	return nil
}
func (w CasbinWatcherEx) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	return nil
}

func (w CasbinWatcherEx) UpdateForRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

func (w CasbinWatcherEx) UpdateForSavePolicy(model model.Model) error {
	return nil
}

func (w CasbinWatcherEx) UpdateForAddPolicies(sec string, ptype string, rules ...[]string) error {
	return nil
}

func (w CasbinWatcherEx) UpdateForRemovePolicies(sec string, ptype string, rules ...[]string) error {
	return nil
}
