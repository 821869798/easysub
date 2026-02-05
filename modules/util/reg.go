package util

import (
	"errors"
	"log/slog"
	"regexp"
	"sync"
)

var regexpCache sync.Map

func getRegexp(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexpCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexpCache.Store(pattern, re)
	return re, nil
}

// RegGetMatch 尝试在 src 中根据给定的正则表达式 pattern 匹配，并将匹配的分组结果赋给可变参数列表中的字符串指针。
// 如果匹配失败或分组数量与参数数量不匹配，将返回错误。
func RegGetMatch(src, pattern string, args ...*string) error {
	re, err := getRegexp(pattern)
	if err != nil {
		return err
	}
	matches := re.FindStringSubmatch(src)
	if matches == nil {
		return errors.New("no match found")
	}
	// 检查分组数量是否与参数数量一致（matches[0] 是完整匹配，所以忽略）
	if len(matches)-1 != len(args) {
		return errors.New("mismatched number of matches and arguments")
	}
	// 赋值
	for i, arg := range args {
		*arg = matches[i+1] // 跳过 matches[0]
	}
	return nil
}

// RegReplace performs regex-based replacements in the provided source string.
func RegReplace(src, match, rep string, multiline bool) string {
	// Prepare the regex pattern, considering the multiline option.
	modPattern := match
	if multiline {
		modPattern = "(?m)" + match
	}

	// Compile the regex pattern.
	re, err := getRegexp(modPattern)
	if err != nil {
		slog.Error("Regex compilation error", slog.String("error", err.Error()))
		return src // Return original if regex is invalid
	}

	return re.ReplaceAllString(src, rep)
}

func RegFind(src string, match string) bool {
	// 设置正则模式，启用多行模式 (?m) 如果需要的话
	// Go的正则默认支持UTF-8，不需要额外设置
	re, err := getRegexp("(?m)" + match)
	if err != nil {
		return false
	}

	return re.FindStringIndex(src) != nil
}

func RegMatch(src, pattern string) bool {
	re, err := getRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(src)
}
