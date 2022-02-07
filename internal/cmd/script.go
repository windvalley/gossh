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

	"github.com/windvalley/gossh/internal/pkg/configflags"
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
	Short: "Execute a local shell script on target hosts",
	Long: `
Execute a local shell script on target hosts.`,
	Example: `
  # Execute foo.sh on target hosts.
  $ gossh script host[1-3] -e foo.sh -k

  # Remove the copied 'foo.sh' on the target hosts after execution.
  $ gossh script host[1-3] -H hosts.txt -e foo.sh -k -r

  Find more examples at: https://github.com/windvalley/gossh/blob/main/docs/script.md`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := configflags.Config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}

		if scriptFile != "" && !util.FileExists(scriptFile) {
			util.CheckErr(fmt.Sprintf("script '%s' not found", scriptFile))
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		task := sshtask.NewTask(sshtask.ScriptTask, configflags.Config)

		task.SetTargetHosts(args)
		task.SetScriptFile(scriptFile)
		task.SetScriptOptions(destPath, remove, force)

		task.Start()

		util.CobraCheckErrWithHelp(cmd, task.CheckErr())
	},
}

func init() {
	scriptCmd.Flags().StringVarP(&scriptFile, "execute", "e", "",
		"a shell script to be executed on target hosts",
	)

	scriptCmd.Flags().StringVarP(&destPath, "dest-path", "d", "/tmp",
		"path of target hosts where the script will be copied to",
	)

	scriptCmd.Flags().BoolVarP(&remove, "remove", "r", false,
		"remove the copied script after execution",
	)

	scriptCmd.Flags().BoolVarP(&force, "force", "F", false,
		"allow overwrite script file if it already exists on target hosts",
	)
}
