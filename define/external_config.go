package define

type ExternalConfig struct {
	CustomProxyGroups []*ProxyGroupConfig
	RulesetConfigs    []*RulesetConfig
	ClashRuleBase     string
	//SurgeRuleBase          string
	//SurfboardRuleBase      string
	//MellowRuleBase         string
	//QuanRuleBase           string
	//QuanxRuleBase          string
	//LoonRuleBase           string
	//SssubRuleBase          string
	SingboxRuleBase        string
	Rename                 []*RegexMatchConfig
	Emoji                  []*RegexMatchConfig
	Include                []string
	Exclude                []string
	TplArgs                map[string]interface{}
	OverwriteOriginalRules bool
	EnableRuleGenerator    bool
	AddEmoji               bool
	RemoveOldEmoji         bool
}

func NewExternalConfig() *ExternalConfig {
	return &ExternalConfig{
		EnableRuleGenerator: true,
	}
}

type RegexMatchConfig struct {
	Match   string
	Replace string
	Script  string
}

type RulesetConfig struct {
	Group    string
	Url      string
	Interval int
}

func NewRulesetConfig() *RulesetConfig {
	return &RulesetConfig{
		Interval: 86400,
	}
}

func (c *RulesetConfig) Equal(r *RulesetConfig) bool {
	return c.Group == r.Group && c.Url == r.Url && c.Interval == r.Interval
}
