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
  # Login user.
  # Default: $USER
  user: %q

  # Password of the login user.
  # Default: ""
  password: %q

  # Ask for password of login user.
  # Default: false
  ask-pass: %v

  # File that contains the password of login user.
  # Default: ""
  file: %q

  # Identity files of pubkey authentication.
  # Default:
  #   - $HOME/.ssh/id_rsa
  #   - $HOME/.ssh/id_dsa
  identity-files: []

  # Passphrase of the identity files.
  # Default: ""
  passphrase: %q

hosts:
  # File containing target hosts (format: one host per line).
  # Default: ""
  file: %q

  # Port of target hosts.
  # Default: 22
  port: %d

run:
  # Use sudo to execute command/script or fetch files/dirs.
  # Default: false
  sudo: %v

  # Run via sudo as this user.
  # Default: root
  as-user: %s

  # Specify i18n envs when execute command/script.
  # Default: origin i18n value on target hosts
  lang: %q

  # Number of concurrent connections.
  # Default: 1
  concurrency: %d

output:
  # File to which messages are output.
  # Default: ""
  file: %q

  # Output messages in json format.
  # Default: false
  json: %v

  # Show debug messages.
  # Default: false
  verbose: %v

  # Do not output messages to screen (except error messages).
  # Default: false
  quite: %v

timeout:
  # Timeout seconds for connecting each target host.
  # Default: 10 (seconds)
  conn: %d

  # Timeout seconds for executing commands/script on each target host.
  # Default: 0
  command: %d

  # Timeout seconds for running the current gossh task.
  # Default: 0
  task: %d

proxy:
  # Proxy server address, and it will enable proxy if it not null.
  # Default: ""
  server: %q

  # Proxy server port.
  # Default: 22
  port: %d

  # Login user for proxy.
  # Default: value of 'auth.user'
  user: %q

  # Password for proxy.
  # Default: value of 'auth.password'
  password: %q

  # Identity files for proxy.
  # Default: value of 'auth.identity-files'
  identity-files: []

  # Passphrase of the identity files for proxy.
  # Default: value of 'auth.passphrase'
  passphrase: %q
`

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate gossh configuration file",
	Long: `
Generate gossh configuration file.

$PWD/.gossh.yaml has higher priority than $HOME/.gossh.yaml`,
	Example: `
  # Generate default configuration content to screen.
  $ gossh config

  # Generate default configuration file.
  $ gossh config > ~/.gossh.yaml

  # Generate configuration file with customized field values by specifying some global flags.
  $ gossh config -u zhangsan -c 100 -j --timeout.command 20 > ./.gossh.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(
			configTemplate,
			config.Auth.User, config.Auth.Password, config.Auth.AskPass, config.Auth.PassFile, config.Auth.Passphrase,
			config.Hosts.File, config.Hosts.Port,
			config.Run.Sudo, config.Run.AsUser, config.Run.Lang, config.Run.Concurrency,
			config.Output.File, config.Output.JSON, config.Output.Verbose, config.Output.Quiet,
			config.Timeout.Conn, config.Timeout.Command, config.Timeout.Task,
			config.Proxy.Server, config.Proxy.Port, config.Proxy.User, config.Proxy.Password, config.Proxy.Passphrase,
		)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
