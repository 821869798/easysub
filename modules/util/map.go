package util

func StringMapSet[T int | int32 | string | bool | float32](m map[string]interface{}, value T, keys ...string) {
	tmpMap := m
	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		tmpMap1, ok := tmpMap[key].(map[string]interface{})
		if !ok || tmpMap1 == nil {
			tmpMap1 = make(map[string]interface{})
			tmpMap[key] = tmpMap1
		}
		tmpMap = tmpMap1
	}
	tmpMap[keys[len(keys)-1]] = value
}

func StringMapGet[T int | int32 | string | bool | float32](m map[string]interface{}, keys ...string) T {
	tmpMap := m
	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		tmpMap1, ok := tmpMap[key].(map[string]interface{})
		if !ok || tmpMap1 == nil {
			tmpMap1 = make(map[string]interface{})
			tmpMap[key] = tmpMap1
		}
		tmpMap = tmpMap1
	}
	result, ok := tmpMap[keys[len(keys)-1]]
	if !ok {
		var zero T
		return zero
	}
	i, ok := result.(T)
	return i
}

func StringMapGetMapValue(m map[string]interface{}, keys ...string) map[string]interface{} {
	tmpMap := m
	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		tmpMap1, ok := tmpMap[key].(map[string]interface{})
		if !ok || tmpMap1 == nil {
			tmpMap1 = make(map[string]interface{})
			tmpMap[key] = tmpMap1
		}
		tmpMap = tmpMap1
	}
	result, ok := tmpMap[keys[len(keys)-1]]
	if !ok {
		newMap := make(map[string]interface{})
		tmpMap[keys[len(keys)-1]] = newMap
		return newMap
	}
	i, ok := result.(map[string]interface{})
	if !ok {
		newMap := make(map[string]interface{})
		tmpMap[keys[len(keys)-1]] = newMap
		return newMap
	}
	return i
}
