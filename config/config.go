package config

import (
	"github.com/BurntSushi/toml"
	"github.com/gookit/slog"
)

type AppConfig struct {
	Version       int                     `toml:"version"`
	Common        *AppConfigCommon        `toml:"common"`
	NodePref      *AppConfigNodePref      `toml:"node_pref"`
	ManagedConfig *AppConfigManagedConfig `toml:"managed_config"`
	Template      *AppConfigTemplate      `toml:"template"`
	Advance       *AppConfigAdvance       `toml:"advance"`
}

type AppConfigCommon struct {
	ApiMode               bool     `toml:"api_mode"`
	ApiAccessToken        string   `toml:"api_access_token"`
	DefaultUrl            []string `toml:"default_url"`
	EnableInsert          bool     `toml:"enable_insert"`
	InsertUrl             []string `toml:"insert_url"`
	PrependInsertUrl      bool     `toml:"prepend_insert_url"`
	DefaultExternalConfig string   `toml:"default_external_config"`
	BasePath              string   `toml:"base_path"`
	ClashRuleBase         string   `toml:"clash_rule_base"`
	SingboxRuleBase       string   `toml:"singbox_rule_base"`
	ProxyConfig           string   `toml:"proxy_config"`
	ProxyRuleset          string   `toml:"proxy_ruleset"`
	ProxySubscription     string   `toml:"proxy_subscription"`
	AppendProxyType       bool     `toml:"append_proxy_type"`
}

type AppConfigNodePref struct {
	SortFlag              bool                                  `toml:"sort_flag"`
	ClashProxiesStyle     string                                `toml:"clash_proxies_style"`
	ClashProxyGroupsStyle string                                `toml:"clash_proxy_groups_style"`
	SingboxAddClashModes  bool                                  `toml:"singbox_add_clash_modes"`
	UDPFlag               bool                                  `toml:"udp_flag"`
	TCPFastOpenFlag       bool                                  `toml:"tcp_fast_open_flag"`
	SkipCertVerify        bool                                  `toml:"skip_cert_verify"`
	TLS13Flag             bool                                  `toml:"tls13_flag"`
	FilterDeprecatedNodes bool                                  `toml:"filter_deprecated_nodes"`
	AppendSubUserinfo     bool                                  `toml:"append_sub_userinfo"`
	SingboxRulesets       map[string]*AppConfigRulesetTransform `toml:"singbox_rulesets"`
}

type AppConfigRulesetTransform struct {
	Name      string `toml:"name"`
	UrlFormat string `toml:"url_format"`
}

type AppConfigManagedConfig struct {
	WriteManagedConfig   bool   `toml:"write_managed_config"`
	ManagedConfigPrefix  string `toml:"managed_config_prefix"`
	ConfigUpdateInterval int    `toml:"config_update_interval"`
	ConfigUpdateStrict   bool   `toml:"config_update_strict"`
	QuanxDeviceId        string `toml:"quanx_device_id"`
}

type AppConfigAdvance struct {
	DefaultPort        int    `toml:"default_port"`
	PortEnvVar         string `toml:"port_env"`
	LogLevel           string `toml:"log_level"`
	EnableCache        bool   `toml:"enable_cache"`
	CacheSubscription  int    `toml:"cache_subscription"`
	CacheConfig        int    `toml:"cache_config"`
	CacheRuleset       int    `toml:"cache_ruleset"`
	MaxAllowedRules    int    `toml:"max_allowed_rules"`
	MaxAllowedRulesets int    `toml:"max_allowed_rulesets"`
	EnableFileShare    bool   `toml:"enable_file_share"`
	FileSharePath      string `toml:"file_share_path"`
	EnablePrivateSub   bool   `toml:"enable_private_sub"`
	PrivateSubConfig   string `toml:"private_sub_config"`
}

type AppConfigTemplate struct {
	Globals []*AppConfigKeyValue `toml:"globals"`
}

type AppConfigKeyValue struct {
	Key   string
	Value string
}

var Global *AppConfig
var PrivateSub *AppConfigPrivateSub

func LoadConfig(path string) {

	_, err := toml.DecodeFile(path, &Global)
	if err != nil {
		slog.PanicErr(err)
	}
	if Global.Common == nil || Global.Advance == nil || Global.NodePref == nil {
		slog.Panic("config file format error")
	}
	if Global.NodePref.SingboxRulesets == nil {
		Global.NodePref.SingboxRulesets = make(map[string]*AppConfigRulesetTransform)
	}

	if Global.Advance.EnablePrivateSub && Global.Advance.PrivateSubConfig != "" {
		// load private sub config
		_, err := toml.DecodeFile(Global.Advance.PrivateSubConfig, &PrivateSub)
		if err != nil {
			slog.PanicErr(err)
		}
		PrivateSub.afterPrivateSubLoad()
	}

}
