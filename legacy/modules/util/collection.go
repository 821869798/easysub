package util

// FindString 在字符串切片中查找一个元素，返回索引和是否找到的布尔值
func FindString(arr []string, target string) int {
	for i, v := range arr {
		if v == target {
			return i
		}
	}
	return -1 // 没有找到
}
