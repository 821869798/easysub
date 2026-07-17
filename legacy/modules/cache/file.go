package cache

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/fankit/fancache"
	"time"
)

var (
	fileCacheDir = "cache" // 缓存目录
	fileCache    *fancache.FileCache
)

func FileInit(maxItems int) {
	fc, err := fancache.NewFileCache(fileCacheDir, fancache.WithMaxItems(config.Global.Advance.WebCacheMaxFiles))
	if err != nil {
		panic("failed to initialize file cache: " + err.Error())
	}
	fileCache = fc
}

func FileGet(key string) ([]byte, bool, error) {
	var bytes []byte
	found, err := fileCache.Get(key, &bytes)
	return bytes, found, err
}

func FileSet(key string, value []byte, duration time.Duration) error {
	if err := fileCache.Set(key, value, duration); err != nil {
		return err
	}
	return nil
}
