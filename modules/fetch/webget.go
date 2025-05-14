package fetch

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/821869798/easysub/config"
	"golang.org/x/sync/singleflight"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cacheDir = "cache" // 缓存目录
)

var (
	// cacheMutex 用于保证对 cache 的并发安全访问
	cacheMutex       sync.RWMutex
	cacheFileCount   atomic.Int32
	clientCacheCount atomic.Int32
	clientCache      sync.Map
	requestGroup     singleflight.Group
)

func init() {

	// 尝试创建缓存目录，如果它还不存在
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		// 根据实际情况决定是 panic 还是仅记录错误
		slog.Error("failed to create cache directory", "dir", cacheDir, "error", err)
		// 如果创建失败，可能后续操作都会失败，这里可以考虑是否要继续
	}

	dirEntries, err := os.ReadDir(cacheDir)
	if err != nil {
		// 记录读取目录失败的错误，此时 cacheFileCount 可能不准确
		slog.Error("failed to read cache directory for initial count", "dir", cacheDir, "error", err)
		cacheFileCount.Store(0)
	} else {
		cacheFileCount.Store(int32(len(dirEntries)))
	}
}

func WebGet(targetURL, proxy string, cacheTTL int) (string, error) {
	if cacheTTL <= 0 { // 如果 TTL 无效，则不使用缓存，直接获取
		return fetchWebDirectly(targetURL, proxy)
	}

	cacheKey := targetURL + proxy // 将 URL 和 proxy 组合成唯一的缓存键
	filename := getMD5Hash(cacheKey)
	filePath := filepath.Join(cacheDir, filename)

	cacheMutex.RLock()
	f, err := os.Stat(filePath)
	needNewFile := err != nil

	if err == nil && time.Now().Before(f.ModTime().Add(time.Duration(cacheTTL)*time.Second)) {
		bytes, err := os.ReadFile(filePath)
		cacheMutex.RUnlock()
		if err == nil {
			slog.Info("⭐ cache hit", slog.String("url", targetURL))
			return string(bytes), nil
		}
		slog.Error("Read cache file failed", slog.String("error", err.Error()), slog.String("path", filePath))
	} else {
		cacheMutex.RUnlock()
	}

	v, err, _ := requestGroup.Do(cacheKey, func() (interface{}, error) {
		content, err := fetchWebDirectly(targetURL, proxy)
		if err != nil {
			return "", err
		}

		cacheFile(filename, content, needNewFile)
		return content, nil
	})

	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func cacheFile(fileName string, content string, isAdd bool) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	err := os.WriteFile(filepath.Join(cacheDir, fileName), []byte(content), 0644)
	if err != nil {
		slog.Error("cache file write failed: " + err.Error())
		return
	}
	if isAdd {
		cacheFileCount.Add(1)
	}

	if cacheFileCount.Load() > int32(config.Global.Advance.WebCacheMaxFiles) {
		// 尝试删除旧的缓存
		evictOldestFiles()
	}
}

func getHTTPClient(proxy string) *http.Client {
	if v, ok := clientCache.Load(proxy); ok {
		return v.(*http.Client)
	}

	transport := &http.Transport{}
	if proxy != "" {
		transport.Proxy = ParseProxy(proxy)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// cache many counts, need clear
	if clientCacheCount.Load() > 100 {
		clientCache.Clear()
		clientCacheCount.Store(0)
	}

	clientCache.Store(proxy, client)
	clientCacheCount.Add(1)
	return client
}

func fetchWebDirectly(targetURL, proxy string) (string, error) {
	response, err := getHTTPClient(proxy).Get(targetURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	return string(body), err
}

// fileCacheInfo 用于排序和管理缓存文件
type fileCacheInfo struct {
	path    string
	modTime time.Time
}

// evictOldestFiles 删除最旧的缓存文件，直到文件数量达到 maxCacheFiles 以下
// 此函数假定 cacheMutex 已经被调用者锁定
func evictOldestFiles() {
	dirEntries, err := os.ReadDir(cacheDir)
	if err != nil {
		slog.Error("evictOldestFiles read dir : " + err.Error())
		return
	}

	var files []fileCacheInfo
	for _, entry := range dirEntries {
		if !entry.IsDir() {
			info, err := entry.Info() // fs.FileInfo
			if err != nil {
				slog.Error("read file info error: " + err.Error())
				continue
			}
			files = append(files, fileCacheInfo{
				path:    filepath.Join(cacheDir, entry.Name()),
				modTime: info.ModTime(),
			})
		}
	}

	if len(files) <= config.Global.Advance.WebCacheMaxFiles {
		return // 不需要清理
	}

	// 按修改时间排序（最旧的在前）
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})

	// 删除多余的最旧文件
	cacheFileClearTarget := config.Global.Advance.WebCacheClearCount
	filesToDeleteCount := len(files) - cacheFileClearTarget
	if filesToDeleteCount <= 0 {
		return
	}
	for i := 0; i < filesToDeleteCount; i++ {
		err := os.Remove(files[i].path)
		if err != nil {
			slog.Error("evictOldestFiles remove file error ", slog.String("path", files[i].path), slog.String("error", err.Error()))
		}
	}
	cacheFileCount.Store(int32(cacheFileClearTarget))
}

// getMD5Hash 为给定的文本生成 MD5 哈希字符串
func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
