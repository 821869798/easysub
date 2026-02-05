package define

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/modules/fetch"
	"github.com/821869798/fankit/fanpath"
	"log/slog"
	"runtime"
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

func (l *RulesetContent) GetRuleSetName() string {
	if len(l.RulePath) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, path := range l.RulePath {
		if i > 0 {
			sb.WriteByte('_')
		}
		sb.WriteString(fanpath.GetFileNameWithoutExt(path))
	}
	return sb.String()
}

func GetRulesetContentName(rulePath []string) string {
	if len(rulePath) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, path := range rulePath {
		if i > 0 {
			sb.WriteByte('_')
		}
		sb.WriteString(fanpath.GetFileNameWithoutExt(path))
	}
	return sb.String()
}

func ParseRulesetContents(rulesetConfig []*RulesetConfig) []*RulesetContent {
	var wg sync.WaitGroup
	maxConcurrent := runtime.GOMAXPROCS(0) * 4
	if maxConcurrent < 4 {
		maxConcurrent = 4
	}
	sem := make(chan struct{}, maxConcurrent)

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
		sem <- struct{}{}
		go func(idx int, ruleUrl, ruleGroup, ruleUrlTyped string, ruleType RulesetType, interval int) {
			defer wg.Done()
			defer func() { <-sem }()

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
			var sb strings.Builder
			sb.Grow(len(lastContent.RuleContent) + 1 + len(current.RuleContent))
			sb.WriteString(lastContent.RuleContent)
			sb.WriteByte('\n')
			sb.WriteString(current.RuleContent)
			lastContent.RuleContent = sb.String()
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

func CreateRulesetContentFromUrls(urls []string, group string, ruleType RulesetType) *RulesetContent {
	var wg sync.WaitGroup
	maxConcurrent := runtime.GOMAXPROCS(0) * 4
	if maxConcurrent < 4 {
		maxConcurrent = 4
	}
	sem := make(chan struct{}, maxConcurrent)
	results := make([]string, len(urls))
	rulesetContent := &RulesetContent{
		RuleGroup: group,
		RulePath:  urls,
	}
	for idx, url := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, url string) {
			defer wg.Done()
			content, _ := fetch.FetchFile(url, config.Global.Common.ProxyRuleset, config.Global.Advance.CacheRuleset, false)
			results[idx] = content
			<-sem
		}(idx, url)
	}
	wg.Wait()
	rulesetContent.RuleContent = strings.Join(results, "\n")

	return rulesetContent
}
