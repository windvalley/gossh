package util

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

// CheckErr and exit.
func CheckErr(msg interface{}) {
	if msg != nil {
		fmt.Fprintln(os.Stderr, color.RedString("Error:"), msg)
		os.Exit(1)
	}
}
