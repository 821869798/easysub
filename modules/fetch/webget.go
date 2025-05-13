package fetch

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"github.com/821869798/easysub/config"
	"github.com/821869798/fankit/fanpath"
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
	cacheMutex     sync.RWMutex
	cacheFileCount atomic.Int32
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

	// 判断缓存文件是否存在
	if fanpath.ExistFile(filePath) {
		cacheMutex.RLock()
		f, err := os.Stat(filePath)
		if err != nil {
			cacheMutex.RUnlock()
			return "", errors.New("stat file failed: " + err.Error())
		}
		modTime := f.ModTime()
		if time.Now().After(modTime.Add(time.Duration(cacheTTL) * time.Second)) {
			cacheMutex.RUnlock()
			// 缓存超时
			content, err := fetchWebDirectly(targetURL, proxy)
			if err != nil {
				return "", errors.New("fetchWebDirectly: " + err.Error())
			}
			cacheFile(filename, content, false)
			return content, nil
		} else {
			// 使用缓存文件
			bytes, err := os.ReadFile(filePath)
			cacheMutex.RUnlock()
			if err != nil {
				return "", errors.New("os.ReadFile: " + err.Error())
			}
			slog.Info("cache hit", slog.String("url", targetURL), slog.String("filename", filename))
			content := string(bytes)
			return content, nil
		}
	}

	// 没有缓存，直接读取
	content, err := fetchWebDirectly(targetURL, proxy)
	if err != nil {
		return "", errors.New("fetchWebDirectly: " + err.Error())
	}

	cacheFile(filename, content, true)
	return content, nil
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

// fetchDirectly 封装了实际的网络请求逻辑
func fetchWebDirectly(targetURL, proxy string) (string, error) {
	client := &http.Client{}

	if proxy != "" {
		// 使用 ParseProxy 函数配置代理
		// 假设 ParseProxy 在此包中或已导入，并返回 func(*http.Request) (*url.URL, error)
		client.Transport = &http.Transport{
			Proxy: ParseProxy(proxy), // 这是您原始代码中的用法
		}
	}

	response, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err // 读取响应体出错
	}
	content := string(body)

	return content, nil
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
