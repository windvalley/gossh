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
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/internal/pkg/sshtask"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

var (
	shellCommand string
	noSafeCheck  bool
)

var defaultCommandBlacklist = []string{
	"rm",
	"reboot",
	"halt",
	"shutdown",
	"poweroff",
	"init",
	"mkfs",
	"mkfs.*",
	"umount",
	"dd",
}

const commandCmdExamples = `
  Execute command 'uptime' on target hosts.
  $ gossh command host1 host2 -e "uptime" -u zhangsan -k

  Use sudo as root to execute command on target hosts.
  $ gossh command host[1-2] -e "uptime" -u zhangsan -s

  Use sudo as other user 'mysql' to execute command on target hosts.
  $ gossh command host[1-2] -e "uptime" -u zhangsan -s -U mysql

  Find more examples at: https://github.com/windvalley/gossh/blob/main/docs/command.md`

var commandCmd = &cobra.Command{
	Use:   "command [HOST...]",
	Short: "Execute commands on target hosts",
	Long: `
Execute commands on target hosts.`,
	Example: commandCmdExamples,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := configflags.Config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}

		if noSafeCheck {
			log.Debugf("Skip the safety check of commands before execution")
		} else {
			if len(configflags.Config.Run.CommandBlacklist) == 0 {
				configflags.Config.Run.CommandBlacklist = defaultCommandBlacklist
				log.Debugf("Using default command blacklist for the safety check: %s", defaultCommandBlacklist)
			} else {
				log.Debugf("Using custom command blacklist for the safety check: %s", configflags.Config.Run.CommandBlacklist)
			}

			if err := checkCommand(shellCommand, configflags.Config.Run.CommandBlacklist); err != nil {
				util.CheckErr(err)
			}
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
	commandCmd.Flags().BoolVarP(
		&noSafeCheck,
		"no-safe-check",
		"n",
		false,
		"ignore dangerous commands (from '-B,--run.command-blacklist') check",
	)
}

func checkCommand(command string, commandBlacklist []string) error {
	unsafeCommands := make([]string, 0)

	commands := strings.FieldsFunc(command, func(r rune) bool {
		if r == ';' || r == '|' || r == '&' || r == ' ' || r == '\t' || r == '\n' {
			return true
		}
		return false
	})

	for _, cmd := range commands {
		for _, unsafeCmd := range commandBlacklist {
			re := regexp.MustCompile(fmt.Sprintf(`(^|/)%s(?:\s+|;)*$`, unsafeCmd))
			if re.MatchString(cmd) {
				unsafeCommands = append(unsafeCommands, cmd)
				break
			}
		}
	}

	if len(unsafeCommands) > 0 {
		unsafeCommands = util.RemoveDuplStr(unsafeCommands)

		return fmt.Errorf(
			"found dangerous commands: '%s', you can add '-n/--no-safe-check' flag to ignore this check",
			strings.Join(unsafeCommands, ", "),
		)
	}

	return nil
}
