package util

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CobraMarkHiddenGlobalFlags ...
func CobraMarkHiddenGlobalFlags(command *cobra.Command, flags ...string) {
	for _, v := range flags {
		if err := command.Flags().MarkHidden(v); err != nil {
			CheckErr(fmt.Sprintf("cannot mark hidden flag: %s", err))
		}
	}
}

// CobraMarkHiddenGlobalFlagsExcept ...
func CobraMarkHiddenGlobalFlagsExcept(parentCommand *cobra.Command, unhiddenFlags ...string) {
	parentCommand.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if !contains(unhiddenFlags, flag.Name) {
			flag.Hidden = true
		}
	})
}

func contains(items []string, i string) bool {
	for _, v := range items {
		if v == i {
			return true
		}
	}

	return false
}
