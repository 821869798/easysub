//go:build !windows

package fetch

import (
	"net/http"
	"net/url"
)

func ParseProxy(proxy string) func(*http.Request) (*url.URL, error) {
	switch proxy {
	case "SYSTEM", "System", "system":
		return http.ProxyFromEnvironment
	case "NONE", "None", "none", "":
		return nil
	default:
		break
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil
	}
	return http.ProxyURL(proxyURL)
}
