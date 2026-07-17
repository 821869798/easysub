package util

import (
	"hash/fnv"
	"strconv"
)

func Str2UInt16(str string) uint16 {
	i, _ := strconv.Atoi(str)
	return uint16(i)
}

func Str2Int(str string) int {
	i, _ := strconv.Atoi(str)
	return i
}

// HashToString 模拟 C++ 的 hash_ 和 std::to_string
func HashToString(str string) string {
	// 创建 FNV-1a 64 位哈希
	h := fnv.New64a()
	// 写入字符串（作为字节切片）
	_, _ = h.Write([]byte(str))
	// 获取哈希值（uint64）
	hashValue := h.Sum64()
	// 转换为字符串
	return strconv.FormatUint(hashValue, 10)
}
