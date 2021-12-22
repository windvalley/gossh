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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/sshtask"
	"github.com/windvalley/gossh/pkg/util"
)

var (
	scriptFile string
	destPath   string
	remove     bool
	force      bool
)

// scriptCmd represents the script command
var scriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Execute a local shell script on remote hosts",
	Long: `
Execute a local shell script on remote hosts`,
	Example: `
  # Execute foo.sh on host1.
  $ gossh script host1 -e foo.sh

  # Remove the remote copied shell script after	execution.
  $ gossh script host1 -e foo.sh -r

  # Use sudo as root to execute foo.sh on host1.
  # NOTE: this will prompt for a password(login user).
  $ gossh script host1 -e foo.sh -s

  # Use sudo as user 'zhangsan' to execute foo.sh on host1.
  # NOTE: this will prompt for a password(login user).
  $ gossh script host1 -e foo.sh -s -U zhangsan`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}

		if scriptFile != "" && !util.FileExists(scriptFile) {
			util.CheckErr(fmt.Sprintf("script '%s' not found", scriptFile))
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		task := sshtask.NewTask(sshtask.ScriptTask, config)

		task.SetHosts(args)
		task.SetScriptFile(scriptFile)
		task.SetScriptOptions(destPath, remove, force)

		task.Start()
	},
}

func init() {
	rootCmd.AddCommand(scriptCmd)

	scriptCmd.Flags().StringVarP(&scriptFile, "execute", "e", "",
		"a shell script to be executed on remote hosts",
	)
	if err := scriptCmd.MarkFlagRequired("execute"); err != nil {
		util.CheckErr(err)
	}

	scriptCmd.Flags().StringVarP(&destPath, "dest-path", "d", "/tmp",
		"path of remote hosts where the script will be copied to",
	)

	scriptCmd.Flags().BoolVarP(&remove, "remove", "r", false,
		"remove the copied script after execution",
	)

	scriptCmd.Flags().BoolVarP(&force, "force", "F", false,
		"allow overwrite script file if it already exists on remote hosts",
	)
}
