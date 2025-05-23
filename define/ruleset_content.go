package define

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/modules/fetch"
	"github.com/821869798/fankit/fanpath"
	"log/slog"
	"strings"
	"sync"
)

//enum ruleset_type
//{
//RULESET_SURGE,
//RULESET_QUANX,
//RULESET_CLASH_DOMAIN,
//RULESET_CLASH_IPCIDR,
//RULESET_CLASH_CLASSICAL
//};

// enum ruleset_type
type RulesetType int

const (
	RULESET_SURGE RulesetType = iota
	RULESET_QUANX
	RULESET_CLASH_DOMAIN
	RULESET_CLASH_IPCIDR
	RULESET_CLASH_CLASSICAL
)

var RulesetTypes = map[string]RulesetType{
	"clash-domain:": RULESET_CLASH_DOMAIN,
	"clash-ipcidr:": RULESET_CLASH_IPCIDR,
	"clash:":        RULESET_CLASH_CLASSICAL,
	"quanx:":        RULESET_QUANX,
	"surge:":        RULESET_SURGE,
}

type RulesetContent struct {
	RuleGroup      string
	RulePath       []string
	RulePathTyped  string
	RuleType       RulesetType
	RuleContent    string
	UpdateInterval int
}

func (r *RulesetContent) GetRuleSetName() string {
	if len(r.RulePath) == 0 {
		return ""
	}
	name := ""
	for _, path := range r.RulePath {
		name += fanpath.GetFileNameWithoutExt(path) + "_"
	}
	// trim end _
	name = name[:len(name)-1]
	return name
}

func ParseRulesetContents(rulesetConfig []*RulesetConfig) []*RulesetContent {
	var wg sync.WaitGroup

	// 预先分配结果切片，保证顺序
	// 不用加锁，每个索引位置是独立的，slice本身不会再被修改
	rulesetContents := make([]*RulesetContent, len(rulesetConfig))

	for idx, x := range rulesetConfig {
		ruleGroup := x.Group
		ruleUrl := x.Url

		pos := strings.Index(x.Url, "[]")
		if pos != -1 {
			//slog.Info(fmt.Sprintf("Adding rule '%s,%s'.", ruleUrl[pos+2:], ruleGroup))
			slog.Info("Adding rule", slog.String(ruleUrl[pos+2:], ruleGroup))

			rulesetContents[idx] = &RulesetContent{
				RuleGroup:   ruleGroup,
				RuleContent: ruleUrl[pos:],
				RuleType:    RULESET_SURGE,
			}
			continue
		}

		ruleType := RULESET_SURGE
		ruleUrlTyped := ruleUrl

		for prefix, t := range RulesetTypes {
			if strings.HasPrefix(ruleUrl, prefix) {
				ruleType = t
				ruleUrlTyped = ruleUrl[len(prefix):]
				break
			}
		}

		wg.Add(1)

		// 并发执行 FetchFile，但通过索引idx存储结果
		go func(idx int, ruleUrl, ruleGroup, ruleUrlTyped string, ruleType RulesetType, interval int) {
			defer wg.Done()

			//slog.Info(fmt.Sprintf("Updating ruleset url '%s' with group '%s'.", ruleUrl, ruleGroup))
			slog.Info("Updating ruleset", slog.String("url", ruleUrl), slog.String("ruleGroup", ruleGroup))

			content, _ := fetch.FetchFile(ruleUrl, config.Global.Common.ProxyRuleset, config.Global.Advance.CacheRuleset, false)

			rc := &RulesetContent{
				RuleGroup:      ruleGroup,
				RulePath:       []string{ruleUrl},
				RulePathTyped:  ruleUrlTyped,
				RuleType:       ruleType,
				UpdateInterval: interval,
				RuleContent:    content,
			}

			rulesetContents[idx] = rc
		}(idx, ruleUrl, ruleGroup, ruleUrlTyped, ruleType, x.Interval)
	}

	wg.Wait()

	// Merge adjacent RulesetContent entries with the same RuleType
	rulesetContents = mergeAdjacentRulesets(rulesetContents)

	return rulesetContents
}

func mergeAdjacentRulesets(contents []*RulesetContent) []*RulesetContent {
	var merged []*RulesetContent
	for i := 0; i < len(contents); i++ {
		current := contents[i]
		if i > 0 && current.RulePathTyped != "" && current.RuleGroup == merged[len(merged)-1].RuleGroup {
			lastContent := merged[len(merged)-1]
			lastContent.RuleContent += "\n" + current.RuleContent
			lastContent.RulePath = append(lastContent.RulePath, current.RulePath...)
		} else {
			merged = append(merged, &RulesetContent{
				RuleGroup:      current.RuleGroup,
				RulePath:       current.RulePath,
				RulePathTyped:  current.RulePathTyped,
				RuleType:       current.RuleType,
				RuleContent:    current.RuleContent,
				UpdateInterval: current.UpdateInterval,
			})
		}
	}
	return merged
}
