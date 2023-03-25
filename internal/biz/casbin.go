package biz

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/go-kratos/kratos/v2/transport/http"

	"gorm.io/gorm"

	v1 "sso/api/casbin/v1"
	"sso/internal/conf"
)

// 鉴权类型
const (
	CasbinObjTypeApi    CasbinObjType = "api"
	CasbinObjTypeMenu   CasbinObjType = "menu"
	CasbinObjTypeTenant CasbinObjType = "tenant"
)

type CasbinObjType string
type Casbin struct {
	db      *gorm.DB
	c       *conf.Casbin
	watcher persist.WatcherEx
}

func NewCasbinFromGorm(db *gorm.DB, watcher persist.WatcherEx, c *conf.Casbin) *Casbin {
	return &Casbin{db, c, watcher}
}

// rbac模型中 主要需要调用的方法
// AddRoleForUser 绑定用户名角色
// DeleteRoleForUser 删除绑定关系
// AddPermissionForUser 添加权限
// DeletePermissionForUser 删除权限
type Enforcer struct {
	e      *casbin.Enforcer
	m      model.Model
	casbin *Casbin
}

// NewEnforcer
func NewEnforcer(c *Casbin, m model.Model) (*Enforcer, error) {
	// Initialize  casbin adapter
	adapter, err := gormadapter.NewAdapterByDBUseTableName(c.db, c.c.GetGorm().GetPrefix(), c.c.GetGorm().GetTable())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize casbin adapter: %v", err)
	}

	// Load model configuration file and policy store adapter
	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %v", err)
	}
	// enforcer.AddFunction("BWIpMatch", c.BWIpMatch)
	enforcer.SetWatcher(c.watcher)
	return &Enforcer{enforcer, m, c}, nil
}

// Authorize casbin 统一鉴权
// Authorize determines if current user has been authorized to take an action on an apiect.
func (enforcer *Enforcer) Authorize(sub string, tpy CasbinObjType, obj string, domain, clientIP string) (bool, error) {
	// Load policy from Database
	err := enforcer.e.LoadPolicy()
	if err != nil {
		return false, v1.ErrorContentMissing("LoadPolicy error")
	}

	// Casbin enforces policy
	ok, err := enforcer.e.Enforce(
		sub,
		string(tpy),
		obj,
		domain,
		clientIP,
	)
	if err != nil || !ok {
		return false, v1.ErrorAuthError("Enforce error")
	}
	return true, nil
}
func (enforcer *Enforcer) AuthorizeUserApiFromHttp(uid string, r *http.Request) (bool, error) {
	// Extract client IP address from request headers
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	var (
		user   = enforcer.casbin.c.GetUserPrefix() + uid
		api    = r.URL.Path + ":" + r.Method
		domain = r.Form.Get("client_id")
	)
	return enforcer.Authorize(user, CasbinObjTypeApi, api, domain, clientIP)
}

// Rbac权限相关
func (enforcer *Enforcer) AddRoleForUserWithPrefix(user, role string) (bool, error) {
	return enforcer.e.AddRoleForUser(enforcer.casbin.c.GetUserPrefix()+user,
		enforcer.casbin.c.GetRolePrefix()+role)
}

func (enforcer *Enforcer) DeleteRoleForUserWithPrefix(user, role string) (bool, error) {
	return enforcer.e.DeleteRoleForUser(enforcer.casbin.c.GetUserPrefix()+user,
		enforcer.casbin.c.GetRolePrefix()+role)
}

func (enforcer *Enforcer) AddPermissionForUserWithPrefix(user string, typ CasbinObjType, obj, tenant string) (bool, error) {
	return enforcer.e.AddPermissionForUser(
		enforcer.casbin.c.GetUserPrefix()+user,
		string(typ), obj, tenant)
}

func (enforcer *Enforcer) DeletePermissionForUserWithPrefix(user string, typ CasbinObjType, obj, tenant string) (bool, error) {
	return enforcer.e.DeletePermissionForUser(
		enforcer.casbin.c.GetUserPrefix()+user,
		string(typ), obj, tenant)
}

func (enforcer *Enforcer) AddPermissionForRoleWithPrefix(role string, typ CasbinObjType, obj, tenant string) (bool, error) {
	return enforcer.e.AddPermissionForUser(
		enforcer.casbin.c.GetRolePrefix()+role,
		string(typ), obj, tenant)
}

func (enforcer *Enforcer) DeletePermissionForRoleWithPrefix(role string, typ CasbinObjType, obj, tenant string) (bool, error) {
	return enforcer.e.DeletePermissionForUser(
		enforcer.casbin.c.GetRolePrefix()+role,
		string(typ), obj, tenant)
}

// BWIpMatch 支持黑白名单的ip验证
//ipMatch("192.168.2.1", "192.168.2.0/24", true)
func (c *Casbin) BWIpMatch(args ...interface{}) (interface{}, error) {
	rIp := args[0].(string)
	ok := false
	var ips = []string{"127.0.0.1"}
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
func RABCModelWithIpMatch(c *conf.Casbin) model.Model {
	rootUser := fmt.Sprintf("%s%d", c.GetUserPrefix(), 1)
	m := model.NewModel()
	m.AddDef("r", "r", "sub, typ, obj, tenant, ip") // 权限检验入参
	m.AddDef("p", "p", "sub, typ, obj, tenant")     // 权限验参
	m.AddDef("g", "g", "_, _")                      // g的参数为user,role
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == '"+rootUser+"' || g(r.sub, p.sub) && r.typ == p.typ && r.obj == p.obj && r.tenant == p.tenant") // && BWIpMatch(r.ip)
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
