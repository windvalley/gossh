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

	"github.com/windvalley/gossh/internal/pkg/sshtask"
	"github.com/windvalley/gossh/pkg/util"
)

var shellCommand string

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "Execute commands on remote hosts",
	Long: `
Execute given commands on remote hosts.`,
	Example: `
  # Promt password.
  $ gossh exec host1 -e "uptime"

  # Given password by -p flag.
  # gossh exec host1 -e "uptime" -p "your-password"

  # Given user:password from a file.
  # gossh exec host1 host2 -e "uptime" -a auth.txt

  # Use pubkey authentication, if env $SSH_AUTH_SOCK exist, use sshagent auth first.
  $ gossh exec -H hosts.txt -e "uptime" -k

  # Hosts can be given from both flag -H and arguments.
  $ gossh exec host1 host2 -H hosts.txt -e "uptime" -k`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		task := sshtask.NewTask(sshtask.CommandTask, config)

		task.SetHosts(args)
		task.SetCommand(shellCommand)
		task.Start()
	},
}

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringVarP(
		&shellCommand,
		"execute",
		"e",
		"",
		"commands to be executed on remote hosts",
	)
	if err := execCmd.MarkFlagRequired("execute"); err != nil {
		util.CheckErr(err)
	}
}
