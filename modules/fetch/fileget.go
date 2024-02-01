package fetch

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// FileGet 读取本地文件的内容
func FileGet(path string) (string, error) {
	// 检查是否有 ..
	if strings.Contains(path, "..") {
		return "", errors.New("invalid path: contains '..'")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// 从file://URI中获取安全的文件路径，确保不会访问baseDirectory之外的文件
func getSecureFilePath(fileURI string, baseDirectory string) (string, error) {
	// 解析URI
	parsedURI, err := url.Parse(fileURI)
	if err != nil {
		return "", errors.New("invalid URI:" + fileURI + "\n" + err.Error())
	}

	// 获取路径部分（移除开头的 '/' 如果存在）
	path := parsedURI.Path
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	path = strings.ReplaceAll(path, "\\", "/")

	// 清理路径，移除 "..", "." 等
	cleanPath := filepath.Clean(path)

	// 检查是否尝试访问上级目录
	if strings.Contains(cleanPath, "..") {
		return "", errors.New("invalid path: contains '..'")
	}

	// 构建完整路径（基于我们的基础目录）
	fullPath := filepath.Join(baseDirectory, cleanPath)

	// 额外安全检查：确保最终路径仍在基础目录内
	absBase, _ := filepath.Abs(baseDirectory)
	absPath, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absPath, absBase) {
		return "", errors.New("invalid path: outside base directory")
	}

	return fullPath, nil
}
