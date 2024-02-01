package util

import (
	"github.com/821869798/easysub/config"
	"strings"
)

// ConvertToNestedMap 接收一个包含点分隔键的 map 并将其转换为嵌套的 map 结构
func ConvertToNestedMap(flatMap map[string]string) map[string]interface{} {
	nestedMap := make(map[string]interface{})
	for key, value := range flatMap {
		parts := strings.Split(key, ".")
		currentMap := nestedMap

		// 遍历键的每个部分，除了最后一部分
		for i, part := range parts {
			if i == len(parts)-1 {
				currentMap[part] = value
			} else {
				// 如果当前键部分不存在，则创建一个新的 map
				if _, exists := currentMap[part]; !exists {
					currentMap[part] = make(map[string]interface{})
				}
				// 移动到下一层
				currentMap = currentMap[part].(map[string]interface{})
			}
		}
	}
	return nestedMap
}

func ConvertKVToNestedMap(flatMap []*config.AppConfigTemplateKV) map[string]interface{} {
	nestedMap := make(map[string]interface{})
	for _, kv := range flatMap {
		key := kv.Key
		value := kv.Value
		parts := strings.Split(key, ".")
		currentMap := nestedMap
		for i, part := range parts {
			if i == len(parts)-1 {
				currentMap[part] = value
			} else {
				if _, exists := currentMap[part]; !exists {
					currentMap[part] = make(map[string]interface{})
				}
				currentMap = currentMap[part].(map[string]interface{})
			}
		}
	}
	return nestedMap
}
