package clash

const (
	// OptimizeMinCount 使用ruleset inline模式优化要求的最小数量
	OptimizeMinCount = 8
)

type QuotedString string

type ruleSetOptimize struct {
	DomainOptimize []QuotedString
	DomainOrigin   string
	IpCidrOptimize []QuotedString
	IpCidrOrigin   string
}
