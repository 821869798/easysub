package util

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	ipv6RegLists = []string{
		`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`,
		`^((?:[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::((?:([0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4})?)$`,
		`^(::(?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5})|((?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5}::)$`,
	}
)

func IsLink(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "ftp://") || strings.HasPrefix(path, "data:")
}

func IsFileUrl(path string) bool {
	return strings.HasPrefix(path, "file://")
}

// IsIPv4 checks if the given address is a valid IPv4 address.
func IsIPv4(address string) bool {
	matched, _ := regexp.MatchString(`^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$`, address)
	return matched
}

// IsIPv6 checks if the given address is a valid IPv6 address.
func IsIPv6(address string) bool {
	for _, reg := range ipv6RegLists {
		matched, _ := regexp.MatchString(reg, address)
		if matched {
			return true
		}
	}
	return false
}

// GetUrlArg extracts a query parameter from a URL string.
func GetUrlArg(url, request string) string {
	pattern := request + "="
	pos := len(url)
	for pos > 0 {
		pos = strings.LastIndex(url[:pos], pattern)
		if pos != -1 {
			if pos == 0 || url[pos-1] == '&' || url[pos-1] == '?' {
				pos += len(pattern)
				end := strings.Index(url[pos:], "&")
				if end == -1 {
					return url[pos:]
				}
				return url[pos : pos+end]
			}
		} else {
			break
		}
		pos--
	}
	return ""
}

func GetUrlArgUnescape(urlString, request string) string {
	result, _ := url.QueryUnescape(GetUrlArg(urlString, request))
	return result
}
