package fetch

import (
	"errors"
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/modules/util"
	"github.com/821869798/fankit/fanpath"
)

func FetchFile(path, proxy string, cacheTTL int, findLocal bool) (string, error) {
	var data string
	var err error

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
