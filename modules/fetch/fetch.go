package fetch

import (
	"errors"
	"os"
	"strings"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/modules/util"
	"github.com/821869798/fankit/fanpath"
)

func FetchFile(path, proxy string, cacheTTL int, findLocal bool) (string, error) {
	var data string
	var err error

	// 检查是否是 env: 开头的环境变量引用
	if strings.HasPrefix(path, "env:") {
		// 移除 env: 前缀和后面的所有斜杠
		envName := strings.TrimPrefix(path, "env:")
		envName = strings.TrimLeft(envName, "/")

		// 从环境变量读取值
		envValue := os.Getenv(envName)
		if envValue != "" {
			path = envValue
		}
		// 如果环境变量不存在或为空，保持原值
	}

	if findLocal && fanpath.ExistFile(path) {
		data, err = FileGet(path)
		return data, err
	} else if util.IsLink(path) {
		data, err = WebGet(path, proxy, cacheTTL)
		if err != nil {
			return "", err
		}
		return data, nil
	} else if util.IsFileUrl(path) && config.Global.Advance.EnableFileShare {
		localPath, err := getSecureFilePath(path, config.Global.Advance.FileSharePath)
		if err != nil {
			return "", err
		}
		data, err = FileGet(localPath)
		return data, err
	}
	return "", errors.New("no valid source found")
}
