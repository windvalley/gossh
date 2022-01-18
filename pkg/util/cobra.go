/*
Copyright © 2021 windvalley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package util

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CobraCheckErrWithHelp instead of cobra default behavior.
func CobraCheckErrWithHelp(cmd *cobra.Command, errMsg interface{}) {
	if errMsg != nil {
		PrintErr(errMsg)

		_ = cmd.Help()

		fmt.Println()

		CheckErr(errMsg)
	}
}

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
