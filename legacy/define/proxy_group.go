package define

type ProxyGroupType int

const (
	ProxyGroupType_Select ProxyGroupType = iota
	ProxyGroupType_URLTest
	ProxyGroupType_LoadBalance
	ProxyGroupType_Fallback
	ProxyGroupType_Relay
	ProxyGroupType_SSID
	ProxyGroupType_Smart
)

type BalanceStrategy int

const (
	BalanceStrategy_ConsistentHashing BalanceStrategy = iota
	BalanceStrategy_RoundRobin
)

type ProxyGroupConfig struct {
	Name              string
	Type              ProxyGroupType
	Proxies           []string
	UsingProvider     []string
	Url               string
	Interval          int
	Timeout           int
	Tolerance         int
	Strategy          BalanceStrategy
	Lazy              Tribool
	DisableUdp        Tribool
	Persistent        Tribool
	EvaluateBeforeUse Tribool
}

func (p *ProxyGroupConfig) TypeStr() string {
	switch p.Type {
	case ProxyGroupType_Select:
		return "select"
	case ProxyGroupType_URLTest:
		return "url-test"
	case ProxyGroupType_LoadBalance:
		return "load-balance"
	case ProxyGroupType_Fallback:
		return "fallback"
	case ProxyGroupType_Relay:
		return "relay"
	case ProxyGroupType_SSID:
		return "ssid"
	case ProxyGroupType_Smart:
		return "smart"
	}
	return ""
}

func (p *ProxyGroupConfig) StrategyStr() string {
	switch p.Strategy {
	case BalanceStrategy_ConsistentHashing:
		return "consistent-hashing"
	case BalanceStrategy_RoundRobin:
		return "round-robin"
	}
	return ""
}
