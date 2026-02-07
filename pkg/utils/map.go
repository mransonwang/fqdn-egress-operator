package utils

func MapContains(superset, subset map[string]string) bool {
	if len(subset) > len(superset) {
		return false
	}

	for k, v := range subset {
		if actual, ok := superset[k]; !ok || actual != v {
			return false
		}
	}
	return true
}
