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
)

const configTemplate = `auth:
  # login user (default is $USER).
  user: %q
  # password of the login user.
  password: %q
  # ask for password of login user.
  ask-pass: %v
  # file that contains 'username:password'.
  file: %q
  # use pubkey authentication.
  # identity files.
  # default:
  #   - $HOME/.ssh/id_rsa
  #   - $HOME/.ssh/id_dsa
  identity-files:
    -
  # passphrase of the identity files.
  passphrase: %q

hosts:
  # file containing target hosts (format: one host per line).
  file: %q
  # port of target hosts.
  # default: 22
  port: %d

run:
  # use sudo to execute the command.
  sudo: %v
  # run via sudo as this user.
  # default: root
  as-user: %q
  # specify i18n envs when execute command/script.
  lang: %q
  # number of concurrent connections.
  # default: 1
  concurrency: %d

output:
  # file to which messages are output.
  file: %q
  # output messages in json format
  json: %v
  # show debug messages.
  verbose: %v
  # do not output messages to screen (except error messages).
  quite: %v

timeout:
  # timeout for connecting each remote host.
  # default: 10 (seconds)
  conn: %d
  # timeout for executing commands/script on each remote host.
  command: %d
  # timeout for the current gossh task.
  task: %d
`

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate gossh configuration file",
	Long: `
Generate gossh configuration file.`,
	Example: `
  # Generate default configuration content to screen.
  $ gossh config

  # Generate default configuration file.
  $ gossh config > ~/.gossh.yaml

  # Generate configuration file with customized field values by specifying some global flags.
  $ gossh config -u zhangsan -c 100 -j --timeout.command 20 > ~/.gossh.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(
			configTemplate,
			config.Auth.User, config.Auth.Password, config.Auth.AskPass, config.Auth.File, config.Auth.Passphrase,
			config.Hosts.File, config.Hosts.Port,
			config.Run.Sudo, config.Run.AsUser, config.Run.Lang, config.Run.Concurrency,
			config.Output.File, config.Output.JSON, config.Output.Verbose, config.Output.Quiet,
			config.Timeout.Conn, config.Timeout.Command, config.Timeout.Task,
		)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
