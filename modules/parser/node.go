package parser

import (
	"errors"
	"github.com/821869798/easysub/define"
	"log/slog"
	"strings"

	"github.com/821869798/easysub/modules/util"
	"github.com/821869798/fankit/fanpath"
)

type ParseSettings struct {
	Proxy      string
	Authorized bool
}

func ParseNode(link string, groupID uint32, settings *ParseSettings) (*define.Proxy, error) {
	// 简化的链接预处理，移除双引号
	link = strings.ReplaceAll(link, "\"", "")

	var customGroup, strSub string
	linkType := define.ConfType_Unknow
	_ = customGroup
	_ = strSub

	// todo script

	node := define.NewProxy()

	//tag:group_name,link
	if strings.HasPrefix(link, "tag:") {
		pos := strings.Index(link, ",")
		if pos != -1 {
			customGroup = link[4:pos] // 提取从 "tag:" 后到逗号前的子字符串
			link = link[pos+1:]       // 更新 link 为逗号后的部分
		}
	}

	if link == "nullnode" {
		node.GroupId = 0
		slog.Debug("Adding node placeholder...")
		return node, nil
	}

	if strings.HasPrefix(link, "https://t.me/socks") || strings.HasPrefix(link, "tg://socks") {
		linkType = define.ConfType_SOCKS
	} else if strings.HasPrefix(link, "https://t.me/http") || strings.HasPrefix(link, "tg://http") {
		linkType = define.ConfType_HTTP
	} else if util.IsLink(link) || strings.HasPrefix(link, "surge:///install-config") {
		linkType = define.ConfType_SUB
	} else if strings.HasPrefix(link, "Netch://") {
		linkType = define.ConfType_Netch
	} else if fanpath.ExistFile(link) {
		linkType = define.ConfType_Local
	}

	switch linkType {

	case define.ConfType_SUB:
		/*
			slog.Debug("Downloading subscription data...")
			if strings.HasPrefix(link, "surge:///install-config") {
				// 解析URL
				u, err := url.Parse(link)
				if err != nil {
					return nil, err
				}
				link = u.Query().Get("url")
			}
			var err error
			strSub, err = fetch.WebGet(link, settings.Proxy, config.Global.Advance.CacheSubscription)
			if err != nil {
				return nil, err
			}
		*/
	case define.ConfType_Local:
		break
	default:
		explode(link, node)
		if node.Type == define.ProxyType_Unknown {
			slog.Error("Failed to parse link: " + link)
			return nil, errors.New("Failed to parse link: " + link)
		}
		node.GroupId = groupID
		return node, nil
	}

	return nil, nil
}
