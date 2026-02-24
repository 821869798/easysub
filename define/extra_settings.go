package define

import "github.com/821869798/easysub/config"

type ExtraSettings struct {
	NodePref                   *config.AppConfigNodePref
	AppendProxyType            Tribool
	SkipCertVerify             Tribool
	FilterDeprecated           Tribool
	UDP                        Tribool
	TFO                        Tribool
	ManagedConfigPrefix        string
	ClashScript                bool
	EnableRuleGenerator        bool
	OverwriteOriginalRules     bool
	ClashRuleSetOptimize       bool
	ClashGeoConvertRuleSet     bool
	ClashRulesetOptimizeToHttp bool
	RequestHost                string
	RequestHostWithProtocol    string
	UserAgent                  string
}

func NewExtraSettings() *ExtraSettings {
	return &ExtraSettings{
		OverwriteOriginalRules: true,
		EnableRuleGenerator:    true,
	}
}
