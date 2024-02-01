//go:build windows

package fetch

import (
	"golang.org/x/sys/windows/registry"
	"net/http"
	"net/url"
)

func ParseProxy(proxy string) func(*http.Request) (*url.URL, error) {
	switch proxy {
	case "SYSTEM", "System", "system":
		proxyEnable, _ := ReadRegistryInt(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable")
		if proxyEnable != 0 {
			proxyServer, err := ReadRegistryString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer")
			if err != nil {
				return nil
			}
			proxy = "http://" + proxyServer
			break
		} else {
			return nil
		}
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

func ReadRegistryString(path, key string) (string, error) {
	// 打开注册表项
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	// 获取注册表键
	value, _, err := k.GetStringValue(key)
	if err != nil {
		return "", err
	}
	return value, nil
}

func ReadRegistryInt(path, key string) (uint64, error) {
	// 打开注册表项
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()

	// 获取注册表键
	value, _, err := k.GetIntegerValue(key)
	if err != nil {
		return 0, err
	}
	return value, nil
}
