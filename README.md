# GoSSH

[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://go.dev)
[![Github Workflow Status](https://img.shields.io/github/workflow/status/windvalley/gossh/GosshCI)](https://github.com/windvalley/gossh/actions/workflows/gosshci.yaml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=windvalley_gossh&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=windvalley_gossh)
[![Version](https://img.shields.io/github/v/release/windvalley/gossh?include_prereleases)](https://github.com/windvalley/gossh/releases)
[![LICENSE](https://img.shields.io/github/license/windvalley/gossh)](LICENSE)

Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands, execute script file, transfer file, etc.

## Features

- Supports three types of ssh tasks.  
  `exec`: Execute commands in remote hosts.  
  `script`: Execute a local script in remote hosts.  
  `push`: Push a local file to remote hosts.

- Supports using sudo to execute the commands or a script as other user(default is `root`).

- Supports specifying i18n environment variable value while executing commands or a script to help keep the language of the outputs consistent. For example: `zh_CN.UTF-8`, `en_US.UTF-8`.

- Supports four authentication methods.  
  Priority: `ssh-agent authentication` -> `pubkey authentication` -> `password from command flag` -> `username:password from a file`.  
  If the user is not specified, the system environment variable `$USER` will be used by default.

- Supports two methods to specify target hosts. One is through command line arguments, input one or more target hosts, separated by space. The other is through command line flag or configuration file option to specify the hosts file. Both methods can be used at the same time.

- Supports three kinds of timeout:  
  Timeout for connecting each remote host (default `10` seconds).  
  Timeout for executing commands or a script on each remote host.  
  Timeout for the current gossh task.

- Supports printing the execution results of `gossh` to a file or screen or to a file and screen at the same time. Supports json format output. Supports printing debug information. Supports silent output.

- High-performance and high-concurrency. You can specify number of concurrent connections (default `1`).

- For ease of use, it supports config file. You can write flags that are not frequently modified into the config file, so you don't need to laboriously specify these flags on the command line. If the flag in both command line and config file, flag that from command line takes precedence over the other. The default config file is: `~/.gossh.yaml`.

- Provide the subcommand `config` to help users generate configuration file in easy way.

## Installation

Prebuilt binaries for macOS and Linux can be downloaded from the [GitHub releases page](https://github.com/windvalley/gossh/releases).

Also you can install `gossh` by compiling:

```sh
$ git clone --depth 1 https://github.com/windvalley/gossh

$ cd gossh

# Note: need to install Go environment first.
$ make && make install
```

## Usage

```sh
$ gossh -h

Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands, execute script file, transfer file, etc.

Usage:
  gossh [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  config      Generate gossh configuration file
  exec        Execute commands in remote hosts
  help        Help about any command
  push        Push a local file to remote hosts
  script      Execute a local script in remote hosts
  version     Show the gossh version information

Flags:
  -a, --auth.file string              file containing the credentials (format: "username:password")
  -i, --auth.identity-files strings   identity files (default is $HOME/.ssh/{id_rsa,id_dsa})
  -p, --auth.password string          password of the login user
  -k, --auth.pubkey                   use pubkey authentication
  -u, --auth.user string              login user (default is $USER)
      --config string                 config file (default is $HOME/.gossh.yaml)
  -h, --help                          help for gossh
  -H, --hosts.file string             file containing target hosts (format: one host per line)
  -P, --hosts.port int                port of target hosts (default 22)
  -o, --output.file string            file to which messages are output
  -j, --output.json                   output messages in json format
  -q, --output.quiet                  do not output messages to screen (except error messages)
  -v, --output.verbose                show debug messages
  -U, --run.as-user string            run via sudo as this user (default "root")
  -c, --run.concurrency int           number of concurrent connections (default 1)
  -l, --run.lang string               specify i18n while executing command (e.g. zh_CN.UTF-8|en_US.UTF-8)
  -s, --run.sudo                      use sudo to execute commands/script
      --timeout.command int           timeout for executing commands/script on each remote host
      --timeout.conn int              timeout for connecting each remote host (default 10)
      --timeout.task int              timeout for the current gossh task

Use "gossh [command] --help" for more information about a command.
```

## License

This project is under the MIT License.
See the [LICENSE](LICENSE) file for the full license text.
