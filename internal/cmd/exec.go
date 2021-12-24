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
Execute commands on remote hosts.`,
	Example: `
  # Promt password.
  $ gossh exec host1 -e "uptime"

  # Get password by '-p' flag.
  # gossh exec host1 -e "uptime" -p "your-password"

  # Get 'user:password' from a file.
  # gossh exec host1 host2 -e "uptime" -a auth.txt

  # Use pubkey authentication, if env $SSH_AUTH_SOCK exist, use ssh-agent auth first.
  $ gossh exec -H hosts.txt -e "uptime" -k

  # Specify login user instead of default $USER.
  $ gossh exec host1 -u zhangsan -e "uptime"

  # Hosts can be given from both arguments and '-H' flag.
  $ gossh exec host1 host2 -H hosts.txt -e "uptime" -k

  # Host pattern is also supported.
  $ gossh exec host1 foo[01-03].[beijing,wuhan].bar.com -H hosts.txt -e "uptime" -k

  # Use sudo as root to execute commands on host1.
  # NOTE: this will prompt for a password(login user).
  $ gossh exec host1 -e "uptime" -s

  # Use sudo as user 'zhangsan' to execute commands on host1.
  # NOTE: this will prompt for a password(login user).
  $ gossh exec host1 -e "uptime" -s -U zhangsan

  # Set timeout seconds for executing commands on each remote host.
  $ gossh script host1 host2 -e "uptime" --timeout.command 10`,
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
