# GoSSH

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=windvalley_gossh&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=windvalley_gossh)

Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands, execute script files, transfer files, etc.

## Features

## Installation

```sh
$ git clone --depth 1 https://github.com/windvalley/gossh

$ cd gossh

$ make && make install
```

## Usage Preview

```sh
$ gossh --help

Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands, execute script files, transfer files, etc.

Usage:
  gossh [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  exec        Execute commands in remote hosts
  help        Help about any command
  version     Show the gossh version information

Flags:
  -a, --auth.file string              file containing the credentials (format is "username:password")
  -i, --auth.identity-files strings   specify the identity files (default is $HOME/.ssh/{id_rsa,id_dsa})
  -p, --auth.password string          password of the login user
  -k, --auth.pubkey                   use pubkey auth or not
  -u, --auth.user string              specify the login user (default is $USER)
      --config string                 config file (default is $HOME/.gossh.yaml)
  -h, --help                          help for gossh
  -H, --hosts.file string             the file containing the hosts that to ssh
  -P, --hosts.port int                the port to be used when connecting (default 22)
  -o, --output.file string            the file where the results will be saved
  -j, --output.json                   outputs format is json or not
  -q, --output.quiet                  do not print messages to stdout (only print errors)
  -v, --output.verbose                print debug information or not
  -U, --run.as-user string            run via sudo as this user (default "root")
  -c, --run.concurrency int           number of goroutines to spawn for simultaneous connection attempts (default 1)
  -s, --run.sudo                      use sudo to execute the command
      --timeout.command int           timeout for the command executing on each remote host
      --timeout.conn int              connection timeout for each ssh connection (default 10)
      --timeout.task int              timeout for all ssh connections

Use "gossh [command] --help" for more information about a command.
```

## License

This project is under the MIT License.
See the [LICENSE](LICENSE) file for the full license text.
