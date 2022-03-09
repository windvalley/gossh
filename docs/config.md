# Config

For ease of use, you can use configuration file.
You can write flags that are not frequently changed into the config file, so you don't need to laboriously specify these flags on the command line.
If the flag in both command line and config file, flag that from command line takes precedence over the other.

The default config file is `$PWD/.gossh.yaml` or `$HOME/.gossh.yaml`, and `$PWD/.gossh.yaml` has a higher priority.

Note that the config file is optional, that is, there can be no config file.

## Configuration contents demo

Demo file can be found in git repo by location: `configs/gossh.yaml`, or use command `gossh config` to generate.

```yaml
auth:
  # Default login user.
  # Default: $USER
  user: ""

  # Default password of the login user.
  # Default: ""
  password: ""

  # Ask for password of the login user.
  # Default: false
  ask-pass: false

  # File that holds the default password of login user.
  # Default: ""
  file: ""

  # Default identity files of pubkey authentication.
  # Default:
  #   - $HOME/.ssh/id_rsa
  #   - $HOME/.ssh/id_dsa
  identity-files: []

  # Default passphrase of the identity files.
  # Default: ""
  passphrase: ""

  # File that holds the vault password for encryption and decryption.
  # Default: ""
  vault-pass-file: ""

hosts:
  # Default inventory file that holds the target hosts.
  # Default: ""
  inventory: ""

  # Default port of target hosts.
  # Default: 22
  port: 22

run:
  # Use sudo to run task.
  # Default: false
  sudo: false

  # Run via sudo as this user.
  # Default: root
  as-user: root

  # Export systems environment variables LANG/LC_ALL/LANGUAGE
  # as this value when executing command/script.
  # Available vaules: zh_CN.UTF-8, en_US.UTF-8, etc.
  # Default: "" (null means do not export)
  lang: ""

  # Number of concurrent connections.
  # Default: 1
  concurrency: 1

output:
  # File to which messages are output.
  # Default: ""
  file: ""

  # Output messages in json format.
  # Default: false
  json: false

  # Show debug messages.
  # Default: false
  verbose: false

  # Do not output messages to screen (except error messages).
  # Default: false
  quite: false

timeout:
  # Timeout seconds for connecting each target host.
  # Default: 10 (seconds)
  conn: 10

  # Timeout seconds for executing commands/script on each target host.
  # NOTE: This command timeout includes the connection timeout (timeout.conn).
  # Default: 0
  command: 0

  # Timeout seconds for running the entire gossh task.
  # Default: 0
  task: 0

proxy:
  # Proxy server address. It will enable proxy if it is not null.
  # Default: ""
  server: ""

  # Proxy server port.
  # Default: 22
  port: 22

  # Login user for proxy.
  # Default: value of 'auth.user'
  user: ""

  # Password for proxy.
  # Default: value of 'auth.password'
  password: ""

  # Identity files for proxy.
  # Default: value of 'auth.identity-files'
  identity-files: []

  # Passphrase of the identity files for proxy.
  # Default: value of 'auth.passphrase'
  passphrase: ""
```

## Examples

Generate configuration file by subcommand `config`:

```sh
$ gossh config --hosts.inventory=/path/hosts.txt > ~/.gossh.yaml
```
