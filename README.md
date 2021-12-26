# GoSSH

[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://go.dev)
[![Github Workflow Status](https://img.shields.io/github/workflow/status/windvalley/gossh/GosshCI)](https://github.com/windvalley/gossh/actions/workflows/gosshci.yaml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=windvalley_gossh&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=windvalley_gossh)
[![Version](https://img.shields.io/github/v/release/windvalley/gossh?include_prereleases)](https://github.com/windvalley/gossh/releases)
[![LICENSE](https://img.shields.io/github/license/windvalley/gossh)](LICENSE) <br>
![Page Views](https://views.whatilearened.today/views/github/windvalley/gossh.svg)
[![Traffic Clones Total](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi.sre.im%2Fv1%2Fgithub%2Ftraffic%2Fclones%2Ftotal%3Fgit_user%3Dwindvalley%26git_repo%3Dgossh%26type%3Dcount%26label%3Dclones-total)](https://github.com/windvalley/traffic-clones-api)
[![Traffic Clones Uniques](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi.sre.im%2Fv1%2Fgithub%2Ftraffic%2Fclones%2Ftotal%3Fgit_user%3Dwindvalley%26git_repo%3Dgossh%26type%3Duniques%26label%3Dclones-uniques)](https://github.com/windvalley/traffic-clones-api)
[![Release Download Total](https://img.shields.io/github/downloads/windvalley/gossh/total)](https://github.com/windvalley/gossh/releases)

Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands, execute a shell script, transfer files and dirs, etc.

## Features

- Supports three types of ssh tasks.  
  `exec`: Execute commands on remote hosts.  
  `script`: Execute a local shell script on remote hosts.  
  `push`: Push local files and dirs to remote hosts.

- Supports using sudo to execute the commands or a shell script as other user(default is `root`).

- Supports specifying i18n environment variable value while executing commands or a shell script to help keep the language of the outputs consistent. For example: `zh_CN.UTF-8`, `en_US.UTF-8`.

- Supports four authentication methods.  
  Priority: `ssh-agent authentication` -> `pubkey authentication` -> `password from flag/config` -> `username:password from a file`.  
  It will auto detected the supported authentication methods, and if no legal authentication method is detected, you will be prompted to enter password.  
  If the login user is not specified, the system environment variable `$USER` will be used by default.

- Supports two ways to specify target hosts. One is through command line arguments, input one or more target hosts, separated by space. The other is through command line flag or configuration file option to specify the hosts file. Both ways can be used at the same time.

- Support expanding host patterns that from commandline arguments or a hosts file to host list,
  and deduplicate the host list.  
  Supported host patterns e.g.:

  ```text
  10.16.0.[1-10]
  foo[01-03].bar.com
  foo[01-03,06,12-16].bar.com
  foo[01-03,06,12-16].[beijing,wuhan].bar.com
  foo[01-03,06,12-16].idc[1-3].[beijing,wuhan].bar.com
  ```

- Supports three kinds of timeout:  
  Timeout for connecting each remote host (default `10` seconds).  
  Timeout for executing commands or a shell script on each remote host or pushing each file/dir to each remote host.  
  Timeout for the current `gossh` task.

- Supports printing the execution results of `gossh` to a file or screen or a file and screen at the same time. Supports json format output. Supports printing debug information. Supports silent output.

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
It can efficiently execute commands or a local script on remote servers,
and transfer files and dirs to remote servers.

Find more information at: https://github.com/windvalley/gossh

Usage:
  gossh [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  config      Generate gossh configuration file
  exec        Execute commands on remote hosts
  help        Help about any command
  push        Push local files/dirs to remote hosts
  script      Execute a local shell script on remote hosts
  version     Show the gossh version information

Flags:
  -k, --auth.ask-pass                 ask for password of login user
  -a, --auth.file string              file containing the credentials (format: "username:password")
  -i, --auth.identity-files strings   identity files (default is $HOME/.ssh/{id_rsa,id_dsa})
  -p, --auth.password string          password of the login user
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
      --timeout.command int           timeout seconds for executing commands/script on each remote host or
                                      pushing each file/dir to each remote host
      --timeout.conn int              timeout seconds for connecting each remote host (default 10)
      --timeout.task int              timeout seconds for the current gossh task

Use "gossh [command] --help" for more information about a command.
```

## Performance

Client server: `4vCPUs` and `8GiB`

Target servers: `hosts.list` contains `936` servers distributed in `86` different IDCs across the country.

**Ansible:**

```sh
$ time ansible all -i hosts.list -m command -a "uptime" -k -f 100
```

Output:

```text
...

real    1m18.858s
user    3m18.566s
sys     1m24.263s
```

**Gossh:**

```sh
$ time gossh exec -H hosts.list -e "uptime" -c 100
```

Output:

```text
...

time=2021-12-22 23:06:50 level=info msg=success count: 936, failed count: 0, elapsed: 6.30s

real    0m6.316s
user    0m13.529s
sys     0m0.592s
```

## License

This project is under the MIT License.
See the [LICENSE](LICENSE) file for the full license text.
