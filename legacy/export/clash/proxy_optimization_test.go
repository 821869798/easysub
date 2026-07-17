package clash

import (
	"testing"

	"github.com/821869798/easysub/define"
)

func TestSkippedProxyDoesNotReserveRemark(t *testing.T) {
	nodes := []*define.Proxy{
		{
			Type:          define.ProxyType_Shadowsocks,
			Remark:        "same-name",
			EncryptMethod: "chacha20",
		},
		{
			Type:   define.ProxyType_VMess,
			Remark: "same-name",
		},
	}
	extraSettings := &define.ExtraSettings{
		FilterDeprecated: define.NewTriboolFromBool(true),
	}
	configObject := make(map[string]interface{})

	if err := proxyToClashInternal(nodes, configObject, nil, extraSettings); err != nil {
		t.Fatalf("proxyToClashInternal() error = %v", err)
	}
	proxies := configObject["proxies"].([]CompactObjectMap)
	if len(proxies) != 1 {
		t.Fatalf("proxy count = %d, want 1", len(proxies))
	}
	if got := proxies[0]["name"]; got != "same-name" {
		t.Fatalf("valid proxy name = %v, want same-name", got)
	}
}
