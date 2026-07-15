package fetch

import (
	"github.com/821869798/easysub/modules/cache"
	"golang.org/x/sync/singleflight"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cacheDir = "cache" // 缓存目录
)

var (
	clientCacheCount atomic.Int32
	clientCache      sync.Map
	clientCacheMu    sync.Mutex
	requestGroup     singleflight.Group
)

type cachedHTTPClient struct {
	client    *http.Client
	transport *http.Transport
}

func WebGet(targetURL, proxy string, cacheTTL int) (string, error) {
	if cacheTTL <= 0 { // 如果 TTL 无效，则不使用缓存，直接获取
		bs, err := fetchWebDirectly(targetURL, proxy)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}

	cacheKey := targetURL + "\n" + proxy // 将 URL 和 proxy 组合成唯一的缓存键

	data, found, err := cache.FileGet(cacheKey)
	if err != nil {
		return "", err
	}

	if found {
		return string(data), nil
	}

	v, err, _ := requestGroup.Do(cacheKey, func() (interface{}, error) {
		content, err := fetchWebDirectly(targetURL, proxy)
		if err != nil {
			return "", err
		}

		err = cache.FileSet(cacheKey, content, time.Duration(cacheTTL)*time.Second)
		if err != nil {
			return "", err
		}

		return string(content), nil
	})

	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func getHTTPClient(proxy string) *http.Client {
	if v, ok := clientCache.Load(proxy); ok {
		return v.(*cachedHTTPClient).client
	}

	clientCacheMu.Lock()
	defer clientCacheMu.Unlock()

	if v, ok := clientCache.Load(proxy); ok {
		return v.(*cachedHTTPClient).client
	}
	if clientCacheCount.Load() >= 100 {
		clearHTTPClientCache()
	}

	transport := &http.Transport{}
	if proxy != "" {
		transport.Proxy = ParseProxy(proxy)
	}

	entry := &cachedHTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		transport: transport,
	}

	clientCache.Store(proxy, entry)
	clientCacheCount.Add(1)
	return entry.client
}

func clearHTTPClientCache() {
	clientCache.Range(func(key, value interface{}) bool {
		if entry, ok := value.(*cachedHTTPClient); ok {
			entry.transport.CloseIdleConnections()
		}
		clientCache.Delete(key)
		return true
	})
	clientCacheCount.Store(0)
}

func fetchWebDirectly(targetURL, proxy string) ([]byte, error) {
	response, err := getHTTPClient(proxy).Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	return body, err
}
