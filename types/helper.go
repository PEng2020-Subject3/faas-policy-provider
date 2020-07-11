package types

// From https://stackoverflow.com/a/15323988
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
			if b == a {
					return true
			}
	}
	return false
}

func MergeMap(a map[string]string, b map[string]string) {
	for k, v := range b {
    a[k] = v
	}
}