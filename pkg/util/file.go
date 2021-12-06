package util

import (
	"os"
	"strings"
)

// FileExists ...
func FileExists(path string) bool {
	path = rebuildPath(path)

	f, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !f.IsDir()
}

// DirExists ...
func DirExists(path string) bool {
	path = rebuildPath(path)

	f, err := os.Stat(path)
	if err != nil {
		return false
	}

	return f.IsDir()
}

func rebuildPath(path string) string {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(path, "~/") {
		path = strings.Replace(path, "~", homeDir, 1)
	}

	return path
}
