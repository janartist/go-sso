package biz

import (
	"github.com/google/wire"
	"sso/internal/data"
	"sso/internal/server"
	"sso/internal/service"
	"testing"
)

func init() {
	wire.Build(server.ProviderSet, data.ProviderSet, ProviderSet, service.ProviderSet, newApp)
}

func TestEnforce(t *testing.T) {

}
