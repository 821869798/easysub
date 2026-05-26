package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/singbox"
)

func main() {
	// Initialize config using absolute path
	config.LoadConfig(`D:\program\go\easysub\workdir\pref.toml`)

	// Create test proxies for all optimized protocols
	proxies := []*define.Proxy{
		// 1. WireGuard (Endpoint structure check)
		{
			Type:       define.ProxyType_WireGuard,
			Remark:     "TestWG",
			Hostname:   "1.2.3.4",
			Port:       51820,
			SelfIP:     "10.0.0.2/32",
			SelfIPv6:   "fd00::2/128",
			PrivateKey: "aGFoYWhhaGFoYWhhaGFoYWhhaGFoYWhhaGFoYWhhaGE=",
			PublicKey:  "d293b3d3b3d3b3d3b3d3b3d3b3d3b3d3b3d3b3d2b2c=",
			AllowedIPs: "0.0.0.0/0,::/0",
			Mtu:        1420,
			ClientId:   "1, 2, 3",
		},
		// 2. VMess HTTP transport (Host []string check)
		{
			Type:             define.ProxyType_VMess,
			Remark:           "TestVMessHTTP",
			Hostname:         "vmess.test.com",
			Port:             443,
			UserId:           "e52002f2-d8de-48dc-b620-7b2f6b4a6829",
			AlterId:          0,
			EncryptMethod:    "auto",
			TransferProtocol: "http",
			Host:             "vmess.host.com",
			Path:             "/vmess-path",
		},
		// 3. Trojan (Default ALPN & Generic TLS uTLS check)
		{
			Type:       define.ProxyType_Trojan,
			Remark:     "TestTrojan",
			Hostname:   "trojan.test.com",
			Port:       443,
			Password:   "trojan-password",
			TLSSecure:  true,
			ServerName: "trojan.sni.com",
			Fingerprint: "chrome",
		},
		// 4. Hysteria2 (QUIC standard TLS check)
		{
			Type:        define.ProxyType_Hysteria2,
			Remark:      "TestHysteria2",
			Hostname:    "hy2.test.com",
			Port:        443,
			Password:    "hy2-password",
			UpSpeed:     100,
			DownSpeed:   100,
			TLSSecure:   true,
			ServerName:  "hy2.sni.com",
			Fingerprint: "firefox",
		},
		// 5. Snell (Unsupported, should trigger warning and skip, NOT empty map)
		{
			Type:     define.ProxyType_Snell,
			Remark:   "TestSnell",
			Hostname: "snell.test.com",
			Port:     8080,
			Password: "snell-password",
		},
	}

	// Read base conf
	baseConfBytes, err := os.ReadFile(`D:\program\go\easysub\workdir\base\singbox.liquid`)
	if err != nil {
		slog.Error("read base conf error: " + err.Error())
		return
	}

	// Prepare template arguments
	tplArgs := map[string]interface{}{
		"Request": map[string]interface{}{
			"target": "singbox",
			"singbox": map[string]interface{}{
				"enable_tun": true,
				"ipv6":       true,
			},
		},
		"Global": map[string]interface{}{
			"singbox": map[string]interface{}{
				"log_level": "info",
				"allow_lan": true,
			},
		},
	}

	outRender, err := singbox.RenderTemplate(string(baseConfBytes), tplArgs)
	if err != nil {
		slog.Error("render template error: " + err.Error())
		return
	}

	var ext define.ExtraSettings
	ext.EnableRuleGenerator = true // We want to test dynamic rules generation!
	ext.OverwriteOriginalRules = false

	// Dummy rulesets with correct field types and formats
	rulesetContent := []*define.RulesetContent{
		{
			RuleGroup:   "proxy",
			RulePath:    []string{"geosite/google"},
			RuleType:    define.RULESET_SURGE,
			RuleContent: "[]GEOSITE,google",
		},
		{
			RuleGroup:   "DIRECT",
			RulePath:    []string{"geoip/cn"},
			RuleType:    define.RULESET_SURGE,
			RuleContent: "[]GEOIP,cn",
		},
		{
			RuleGroup:   "proxy",
			RulePath:    []string{"final"},
			RuleType:    define.RULESET_SURGE,
			RuleContent: "[]FINAL,proxy",
		},
	}

	output, err := singbox.ProxyToSingBox(proxies, outRender, rulesetContent, nil, &ext)
	if err != nil {
		slog.Error("proxy to singbox error: " + err.Error())
		return
	}

	// Write to temporary check file in absolute path
	checkFilePath := `D:\program\go\easysub\scratch\generated_test_full.json`
	err = os.WriteFile(checkFilePath, []byte(output), 0644)
	if err != nil {
		slog.Error("write generated_test_full.json error: " + err.Error())
		return
	}
	fmt.Println("Successfully wrote full test config to generated_test_full.json")
}
