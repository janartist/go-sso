package biz

import (
	"github.com/casbin/casbin/v2/persist"
	"github.com/google/wire"
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(
	NewCasbinFromGorm,
	NewEnforcer,
	RABCModelWithIpMatch,
	wire.Bind(new(persist.WatcherEx), new(*CasbinWatcherEx)),
	NewCasbinWatcherEx,
	NewOauth2Server,
)
