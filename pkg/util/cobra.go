package util

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CobraMarkHiddenGlobalFlags that from params.
func CobraMarkHiddenGlobalFlags(command *cobra.Command, flags ...string) {
	for _, v := range flags {
		if err := command.Flags().MarkHidden(v); err != nil {
			CheckErr(fmt.Sprintf("cannot mark hidden flag: %s", err))
		}
	}
}

// CobraMarkHiddenGlobalFlagsExcept the flags from params.
func CobraMarkHiddenGlobalFlagsExcept(parentCommand *cobra.Command, unhiddenFlags ...string) {
	parentCommand.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if !contains(unhiddenFlags, flag.Name) {
			flag.Hidden = true
		}
	})
}

// CobraAddSubCommandInOrder in the order of the subcommand provided.
func CobraAddSubCommandInOrder(rootCommand *cobra.Command, subcommands ...*cobra.Command) {
	cobra.EnableCommandSorting = false

	for _, cmd := range subcommands {
		rootCommand.AddCommand(cmd)

		cmd.Flags().SortFlags = false
	}
}

func contains(items []string, i string) bool {
	for _, v := range items {
		if v == i {
			return true
		}
	}

	return false
}
