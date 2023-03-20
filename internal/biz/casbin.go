package biz

import (
	"fmt"
	"gorm.io/gorm"

	"sso/internal/conf"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/util"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

type Casbin struct {
	db        *gorm.DB
	prefix    string
	tableName string
	model     *model.Model
}
type Enforcer struct {
	*casbin.Enforcer
}

func NewCasbinFromGorm(db *gorm.DB, model *model.Model, c *conf.Casbin) *Casbin {
	return &Casbin{db, c.GetGorm().GetPrefix(), c.GetGorm().GetTable(), model}
}

// NewEnforcer
func NewEnforcer(c *Casbin) *Enforcer {
	// Initialize  casbin adapter
	adapter, err := gormadapter.NewAdapterByDBUseTableName(c.db, c.prefix, c.tableName)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize casbin adapter: %v", err))
	}

	// Load model configuration file and policy store adapter
	enforcer, err := casbin.NewEnforcer(c.model, adapter)
	if err != nil {
		panic(fmt.Sprintf("failed to create casbin enforcer: %v", err))
	}
	return &Enforcer{enforcer}
}

// Authorize casbin 统一鉴权
// Authorize determines if current user has been authorized to take an action on an object.
func (enforcer *Enforcer) Authorize() (bool, error) {
	return true, nil
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
