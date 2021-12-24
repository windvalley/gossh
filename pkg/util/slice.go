package util

// RemoveDuplStr item from slice.
func RemoveDuplStr(strSlice []string) []string {
	set := make([]string, 0)

	keys := make(map[string]bool, len(strSlice))

	for _, v := range strSlice {
		if !keys[v] {
			set = append(set, v)
			keys[v] = true
		}
	}

	return set
}
