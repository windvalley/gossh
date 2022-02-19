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
	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/internal/pkg/sshtask"
	"github.com/windvalley/gossh/pkg/util"
)

var shellCommand string

const commandCmdExamples = `
  # Execute command 'uptime' on target hosts.
  $ gossh command host1 host2 -e "uptime" -u zhangsan -k

  # Use sudo as root to execute command on target hosts.
  $ gossh command host[1-2] -e "uptime" -u zhangsan -s

  Find more examples at: https://github.com/windvalley/gossh/blob/main/docs/command.md`

// commandCmd represents the exec command
var commandCmd = &cobra.Command{
	Use:   "command",
	Short: "Execute commands on target hosts",
	Long: `
Execute commands on target hosts.`,
	Example: commandCmdExamples,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := configflags.Config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		task := sshtask.NewTask(sshtask.CommandTask, configflags.Config)

		task.SetTargetHosts(args)
		task.SetCommand(shellCommand)

		task.Start()

		util.CobraCheckErrWithHelp(cmd, task.CheckErr())
	},
}

func init() {
	commandCmd.Flags().StringVarP(
		&shellCommand,
		"execute",
		"e",
		"",
		"commands to be executed on target hosts",
	)
}
