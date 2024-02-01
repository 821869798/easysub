package fetch

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// CacheItem 用于存储缓存条目和过期时间
type CacheItem struct {
	Content    string
	Expiration time.Time
}

var (
	// cache 用于存储响应内容
	cache = make(map[string]CacheItem)
	// cacheMutex 用于保证对 cache 的并发安全访问
	cacheMutex sync.RWMutex
)

// webGet fetches the content from the specified URL using an optional proxy.
// It includes a caching mechanism.
func WebGet(targetURL, proxy string, cacheTTL int) (string, error) {
	cacheKey := targetURL + proxy // 将 URL 和 proxy 组合成唯一的缓存键

	// 如果提供了有效的 cacheTTL，则尝试使用缓存
	if cacheTTL > 0 {
		cacheMutex.RLock()
		if item, found := cache[cacheKey]; found {
			if time.Now().Before(item.Expiration) {
				cacheMutex.RUnlock()
				return item.Content, nil // 缓存命中，直接返回
			}
		}
		cacheMutex.RUnlock()
	}

	// 创建 HTTP 客户端
	client := &http.Client{}

	// 如果提供了代理URL，配置HTTP客户端使用该代理
	if proxy != "" {
		client.Transport = &http.Transport{
			Proxy: ParseProxy(proxy),
		}
	}

	// 发起 GET 请求
	response, err := client.Get(targetURL)
	if err != nil {
		return "", err // 处理请求错误
	}
	defer response.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err // 读取响应体出错
	}
	content := string(body)

	// 如果 cacheTTL 大于 0，则更新缓存
	if cacheTTL > 0 {
		cacheMutex.Lock()
		cache[cacheKey] = CacheItem{
			Content:    content,
			Expiration: time.Now().Add(time.Duration(cacheTTL) * time.Second),
		}
		cacheMutex.Unlock()
	}

	return content, nil
}
