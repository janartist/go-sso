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
	enforcer.AddFunction("BWIpMatch", c.BWIpMatch)
	enforcer.AddFunction("ObjMatch", c.ObjMatch)
	enforcer.SetWatcher(c.watcher)
	return &Enforcer{enforcer, m, c}, nil
}

// Authorize casbin api鉴权
func (enforcer *Enforcer) Authorize(sub string, typ CasbinObjType, obj, act, domain, clientIP string) (bool, error) {
	// Load policy from Database
	err := enforcer.e.LoadPolicy()
	if err != nil {
		return false, v1.ErrorContentMissing("LoadPolicy error")
	}
	// Casbin enforces policy
	ok, err := enforcer.e.Enforce(
		sub,
		string(typ),
		obj,
		act,
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
		domain = r.Form.Get("client_id")
	)
	return enforcer.Authorize(user, CasbinObjTypeApi, r.URL.Path, r.Method, domain, clientIP)
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

func (enforcer *Enforcer) AddObjPermissionForRoleWithPrefix(role string, typ CasbinObjType, obj, act, tenant string) (bool, error) {
	return enforcer.e.AddNamedPolicy(
		"p",
		enforcer.casbin.c.GetRolePrefix()+role,
		string(typ), obj, act, tenant)
}

func (enforcer *Enforcer) DeleteObjPermissionForRoleWithPrefix(role string, typ CasbinObjType, obj, act, tenant string) (bool, error) {
	return enforcer.e.RemoveNamedPolicy(
		"p",
		enforcer.casbin.c.GetRolePrefix()+role,
		string(typ), obj, act, tenant)
}

// BWIpMatch 支持黑白名单的ip验证
//ipMatch("192.168.2.1", "192.168.2.0/24", true)
func (c *Casbin) BWIpMatch(args ...interface{}) (interface{}, error) {
	return true, nil
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

// ObjMatch("api", "/url/id/:id", "/url/id/1", "(GET)|(POST)", "POST")
// ObjMatch("menu", "menu1", "menu1", "", "")
func (c *Casbin) ObjMatch(args ...interface{}) (interface{}, error) {
	if args[0].(string) == string(CasbinObjTypeApi) {
		return util.KeyMatch2(
			args[1].(string), args[2].(string)) && util.RegexMatch(args[3].(string), args[4].(string)), nil
	}
	return args[1].(string) == args[2].(string) && args[3].(string) == args[4].(string), nil
}

// g为user->role的group
// g2为api->menu的group
func RABCModelWithIpMatch(c *conf.Casbin) model.Model {
	rootUser := fmt.Sprintf("%s%d", c.GetUserPrefix(), 1)
	m := model.NewModel()
	m.AddDef("g", "g", "_, _") // g的参数为user,role
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("r", "r", "sub, typ, obj, act, tenant, ip") // 权限检验入参
	m.AddDef("p", "p", "sub, typ, obj, act, tenant")     // 权限验参
	m.AddDef("m", "m", "r.sub == '"+rootUser+"' || g(r.sub, p.sub) && r.typ == p.typ && ObjMatch(r.typ, r.obj, p.obj, r.act, p.act) && r.tenant == p.tenant && BWIpMatch(r.ip)")
	return m
}

type WatcherObjHandle interface {
	PolicyObjUpdateOrAdd(sub, typ, obj, act, domain string) error
	PolicyRoleUpdateOrAdd(user, role string) error
	PolicyObjRemove(sub, typ, obj, act, domain string) error
	PolicyRoleRemove(user, role string) error
}

func NewCasbinWatcherEx(handle WatcherObjHandle) *CasbinWatcherEx {
	return &CasbinWatcherEx{handle: handle}
}

type CasbinWatcherEx struct {
	callback func(string)
	handle   WatcherObjHandle
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
	fmt.Print("watch UpdateForAddPolicy", sec, ptype, params, "\n")
	if sec == "p" {
		if len(params) == 5 {
			return w.handle.PolicyObjUpdateOrAdd(params[0], params[1], params[2], params[3], params[4])
		}
	}
	if sec == "g" {
		if len(params) == 2 {
			return w.handle.PolicyRoleUpdateOrAdd(params[0], params[1])
		}
	}
	return nil
}
func (w CasbinWatcherEx) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	fmt.Print("watch UpdateForRemovePolicy", sec, ptype, params, "\n")
	if sec == "p" {
		if len(params) == 5 {
			return w.handle.PolicyObjRemove(params[0], params[1], params[2], params[3], params[4])
		}
	}
	if sec == "g" {
		if len(params) == 2 {
			return w.handle.PolicyRoleRemove(params[0], params[1])
		}
	}
	return nil
}

func (w CasbinWatcherEx) UpdateForAddPolicies(sec string, ptype string, rules ...[]string) error {
	fmt.Print("watch UpdateForAddPolicies", sec, ptype, rules, "\n")
	var err error
	for _, rule := range rules {
		err = w.UpdateForAddPolicy(sec, ptype, rule...)
		if err != nil {
			return err
		}
	}
	return err
}

func (w CasbinWatcherEx) UpdateForRemovePolicies(sec string, ptype string, rules ...[]string) error {
	fmt.Print("watch UpdateForRemovePolicies", sec, ptype, rules, "\n")
	var err error
	for _, rule := range rules {
		err = w.UpdateForRemovePolicy(sec, ptype, rule...)
		if err != nil {
			return err
		}
	}
	return err
}

func (w CasbinWatcherEx) UpdateForRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

func (w CasbinWatcherEx) UpdateForSavePolicy(model model.Model) error {
	return nil
}
