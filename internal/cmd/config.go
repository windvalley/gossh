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
	"bytes"
	"fmt"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/util"
)

const configTemplate = `auth:
  # The login user.
  # Default: $USER
  user: {{ .Auth.User }}

  # The password of the login user.
  # Default: ""
  password: {{ .Auth.Password }}

  # Ask for password of the login user.
  # Default: false
  ask-pass: {{ .Auth.AskPass }}

  # File that holds the default password of login user.
  # Default: ""
  file: {{ .Auth.PassFile }}

  # The identity files of pubkey authentication.
  # Default: [~/.ssh/id_rsa]
  identity-files: [~/.ssh/id_rsa]

  # The passphrase of the identity files.
  # Default: ""
  passphrase: {{ .Auth.Passphrase }}

  # File that holds the vault password for encryption and decryption.
  # Default: ""
  vault-pass-file: {{ .Auth.VaultPassFile }}

hosts:
  # Default inventory file that holds the target hosts.
  # The file content format can be referred to at: 
  # https://github.com/windvalley/gossh/blob/main/docs/inventory.md
  # Default: ""
  inventory: {{ .Hosts.Inventory }}

  # Default port of target hosts.
  # Default: 22
  port: {{ .Hosts.Port }}

run:
  # Use sudo to run task.
  # Default: false
  sudo: {{ .Run.Sudo }}

  # Run via sudo as this user.
  # Default: root
  as-user: {{ .Run.AsUser }}

  # Export systems environment variables LANG/LC_ALL/LANGUAGE
  # as this value when executing command/script.
  # Available vaules: zh_CN.UTF-8, en_US.UTF-8, etc.
  # Default: "" (null means do not export)
  lang: {{ .Run.Lang }}

  # Number of concurrent connections.
  # Default: 1
  concurrency: {{ .Run.Concurrency }}

  # Linux Command Blacklist for gossh subcommands 'command' and 'script'.
  # Commands listed in this blacklist will be prohibited from executing on remote hosts for security reasons.
  # You can add flag '-n, --no-safe-check' to disable this feature.
  # Default: [rm, reboot, halt, shutdown, init, mkfs, mkfs.*, umount, dd]
  command-blacklist: [rm, reboot, halt, shutdown, init, mkfs, mkfs.*, umount, dd]

output:
  # File to which messages are output.
  # Default: ""
  file: {{ .Output.File }}

  # Output messages in json format.
  # Default: false
  json: {{ .Output.JSON }}

  # Condense output and disable color.
  # Default: false
  condense: {{ .Output.Condense }}

  # Show debug messages.
  # Default: false
  verbose: {{ .Output.Verbose }}

  # Do not output messages to screen.
  # Default: false
  quite: {{ .Output.Quiet }}

timeout:
  # Timeout seconds for connecting each target host.
  # Default: 10 (seconds)
  conn: {{ .Timeout.Conn }}

  # Timeout seconds for executing commands/script on each target host.
  # NOTE: This command timeout includes the connection timeout (timeout.conn).
  # Default: 0
  command: {{ .Timeout.Command }}

  # Timeout seconds for running the entire gossh task.
  # Default: 0
  task: {{ .Timeout.Task }}

proxy:
  # Proxy server address. It will enable proxy if it is not null.
  # Default: ""
  server: {{ .Proxy.Server }}

  # Proxy server port.
  # Default: 22
  port: {{ .Proxy.Port }}

  # Proxy server user.
  # Default: the same as 'auth.user'
  user: {{ .Proxy.User }}

  # Password for proxy.
  # Default: the same as 'auth.password'
  password: {{ .Proxy.Password }}

  # Identity files for proxy.
  # Default: the same as 'auth.identity-files'
  identity-files:

  # Passphrase of the identity files for proxy.
  # Default: the same as 'auth.passphrase'
  passphrase: {{ .Proxy.Passphrase }}`

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
		var conf bytes.Buffer
		template, err := template.New("config-template").Parse(configTemplate)
		if err != nil {
			util.PrintErrExit(fmt.Errorf("parse config template failed: %w", err))
		}

		config := configflags.Config
		if err := template.Execute(&conf, config); err != nil {
			util.PrintErrExit(fmt.Errorf("render config template failed: %w", err))
		}

		fmt.Println(conf.String())
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
			"run.command-blacklist",
		)

		command.Parent().HelpFunc()(command, strings)
	})
}
