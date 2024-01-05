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
	"os"

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/util"
)

const configTemplate = `auth:
  # Default login user.
  # Default: $USER
  user: %q

  # Default password of the login user.
  # Default: ""
  password: %q

  # Ask for password of the login user.
  # Default: false
  ask-pass: %v

  # File that holds the default password of login user.
  # Default: ""
  file: %q

  # Default identity files of pubkey authentication.
  # Default:
  #   - $HOME/.ssh/id_rsa
  #   - $HOME/.ssh/id_dsa
  identity-files: []

  # Default passphrase of the identity files.
  # Default: ""
  passphrase: %q

  # File that holds the vault password for encryption and decryption.
  # Default: ""
  vault-pass-file: %q

hosts:
  # Default inventory file that holds the target hosts.
  # Default: ""
  inventory: %q

  # Default port of target hosts.
  # Default: 22
  port: %d

run:
  # Use sudo to run task.
  # Default: false
  sudo: %v

  # Run via sudo as this user.
  # Default: root
  as-user: %s

  # Export systems environment variables LANG/LC_ALL/LANGUAGE
  # as this value when executing command/script.
  # Available vaules: zh_CN.UTF-8, en_US.UTF-8, etc.
  # Default: "" (null means do not export)
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
  # NOTE: This command timeout includes the connection timeout (timeout.conn).
  # Default: 0
  command: %d

  # Timeout seconds for running the entire gossh task.
  # Default: 0
  task: %d

proxy:
  # Proxy server address. It will enable proxy if it is not null.
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
Default configuration file path: $PWD/.gossh.yaml and $HOME/.gossh.yaml,
and $PWD/.gossh.yaml has higher priority than $HOME/.gossh.yaml`,
	Example: `
  Generate default configuration content to screen.
  $ gossh config

  Generate default configuration file.
  $ gossh config > ~/.gossh.yaml

  Generate configuration file with customized field values by specifying some global flags.
  $ gossh config -u zhangsan -c 100 -j --timeout.command 20 > ./.gossh.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		config := configflags.Config

		user := config.Auth.User
		if user == os.Getenv("USER") {
			user = ""
		}

		fmt.Printf(
			configTemplate,
			user, config.Auth.Password, config.Auth.AskPass,
			config.Auth.PassFile, config.Auth.Passphrase, config.Auth.VaultPassFile,
			config.Hosts.Inventory, config.Hosts.Port,
			config.Run.Sudo, config.Run.AsUser, config.Run.Lang, config.Run.Concurrency,
			config.Output.File, config.Output.JSON, config.Output.Verbose, config.Output.Quiet,
			config.Timeout.Conn, config.Timeout.Command, config.Timeout.Task,
			config.Proxy.Server, config.Proxy.Port, config.Proxy.User,
			config.Proxy.Password, config.Proxy.Passphrase,
		)
	},
}

func init() {
	configCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		util.CobraMarkHiddenGlobalFlags(
			command,
			"config",
			"auth.identity-files",
			"proxy.identity-files",
			"hosts.list",
		)

		command.Parent().HelpFunc()(command, strings)
	})
}
