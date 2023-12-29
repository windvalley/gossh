# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.13.0]

### Added

Add flag `-z, --zip` for subcommand `push`.

### Changed

Improve the files transfer efficiency of the subcommand `push`.
The subcommand `push` no longer uses zip compression by default. If you want to continue using zip compression, you can add the `-z` flag to the command line.

## [1.12.0]

### Changed

- Optimize help usage information. Add neccessary positional arguments to Usage info for subcommands: `command`, `script`, `push`, `fetch`, `vault encrypt`, `vault decrypt`, `vault encrypt-file`, `vault decrypt-file`, `vault view`.

  E.G.

  ```sh
  $ gossh command -h
  ```

  Output:

  Before:

  ```text
  Execute commands on target hosts.

  Usage:
    gossh command [flags]
  ...
  ```

  Now:

  ```text
  Execute commands on target hosts.

  Usage:
    gossh command [HOST...] [flags]
  ...
  ```

- Flag `-i,--auth.identity-files` changed to `-I,--auth.identity-files`,
  and flag `-H,--hosts.inventory` changed to `-i,--hosts.inventory`.

## [1.11.1]

### Added

- Add documentation.

### Changed

- Optimize examples of subcommand `fetch`.

### Fixed

- Subcommand `config`: `hosts.file` -> `hosts.inventory`.

- `configs/gossh.yaml`: `hosts.file` -> `hosts.inventory`.

## [1.11.0]

### Changed

- Optimize subcommand `config`.

- Update configuration demo file `configs/gossh.yaml`.

- Optimize examples of subcommands.

- Change default tmp dir for subcommand `fetch`.
  Default value of flag `-t, --tmp-dir` changed from `/tmp` to `$HOME`.

- Optimize the priority of the ssh authentication methods.
  Old: `password > pubkey > ssh-agent`,
  New: `ssh-agent > pubkey > password`.
  For details at ([#31](https://github.com/windvalley/gossh/issues/31)).

- Optimize description of flag `--timeout.command`.

### Fixed

- Fix a bug about ssh authentication. The bug description:  
  When attempting ssh-agent fails, pubkey authentication is skipped and password authentication is used directly.

- Fix a bug about ssh-agent authentication method about proxy server.

## [1.10.0]

### Added

- Add feature that getting vault password from an executable file.
  For details at ([#28](https://github.com/windvalley/gossh/issues/28)).

### Changed

- Flag `-L, --hosts.list` changed to `-l, --hosts.list`.

- Flag `-l, --run.lang` changed to `-L, --host.lang`.

- Optimize help description of flag `-V, --auth.vault-pass-file`.

## [1.9.0]

### Added

- Support group hosts, group vars and group combination in inventory file.

  Example inventory file:

```text
# This is a hosts inventory file for gossh

# no group hosts
alias_name_node1 host=node1.sre.im
node100.sre.im

# hosts group
[webserver]
alias_name_node2 host=192.168.33.12 port=8022 user=vagrant password=123456 keys=~/.ssh/id_dsa,~/.ssh/id_rsa passphrase=xxx
node[06-07].sre.im port=9022 user=lisi password=654321
node08.sre.im

# host vars for group webserver
[webserver:vars]
port=8033
user=wangwu

[dbserver]
192.168.1.10

[dbserver:vars]
user=vagrant2
password=abcdefg

# hosts group project1 has hosts that defined in group dbserver and group webserver
[project1:children]
dbserver
webserver
```

For details at ([#29](https://github.com/windvalley/gossh/issues/29)).

### Changed

- Flag `-H, --hosts.file` changed to `-H, --hosts.inventory`.

## [1.8.0]

### Added

- Allow adding variables to inventory(host file), available variables: `host port user password keys passphrase`.

Example host file:

```text
alias_name_node1 host=node1.sre.im
alias_name_node2 host=192.168.33.12 port=22 user=vagrant password=vagrant keys=~/.ssh/id_dsa,~/.ssh/id_rsa passphrase=xxx
node3.sre.im user=vagrant password=GOSSH-AES256:9cfe499133b69a6c7fc62b5b6ba72d3d8dfb4d0e7987170a40c5d50bb5d71e19
```

For details at ([#27](https://github.com/windvalley/gossh/issues/27)).

## [1.7.0]

### Added

- `gossh vault encrypt`: adding the feature of obtaining plaintext from promt.
  For details at ([#24](https://github.com/windvalley/gossh/issues/24)).

- Add following new commands for subcommand `vault`,
  for details at ([#25](https://github.com/windvalley/gossh/issues/25)).
  - `encrypt-file`: Encrypt a file
  - `decrypt-file`: Decrypt vault encrypted file
  - `view`: View vault encrypted file

### Changed

- Hide following global flags for `vault`.

  - `-j/--output.json`
  - `-q/--output.quiet`
  - `-o/--output.file`
  - `-C/--output.condense`

- Optimize some flags description.

## [1.6.0]

### Changed

- Hide global flags that are not used by some subcommands
  ([#21](https://github.com/windvalley/gossh/issues/21)).

  - Hide following global flags for subcommand `config`.

    - `--config`
    - `-i/--auth.identity-files`
    - `--proxy.identity-files`
    - `-L/--hosts.list`

  - Hide all global flags for subcommand `version`.

  - Hide all global flags except following for `vault`.

    - `-V/--auth.vault-pass-file`
    - `-v/--output.verbose`
    - `-j/--output.json`
    - `-q/--output.quiet`
    - `-o/--output.file`
    - `-C/--output.condense`

  - Hide following global flags for subcommand `push`.
    - `-s/--run.sudo`
    - `-U/--run.as-user`
    - `-L/--run.lang`

- Optimize the order of available commands.
  Before:

  ```text
  Available Commands:
  command     Execute commands on target hosts
  completion  Generate the autocompletion script for the specified shell
  config      Generate gossh configuration file
  fetch       Copy files/dirs from target hosts to local
  help        Help about any command
  push        Copy local files/dirs to target hosts
  script      Execute a local shell script on target hosts
  vault       Encryption and decryption utility
  version     Show gossh version information
  ```

  After:

  ```text
  Available Commands:
  command     Execute commands on target hosts
  script      Execute a local shell script on target hosts
  push        Copy local files/dirs to target hosts
  fetch       Copy files/dirs from target hosts to local
  vault       Encryption and decryption utility
  config      Generate gossh configuration file
  version     Show gossh version information
  help        Help about any command
  completion  Generate the autocompletion script for the specified shell
  ```

- Optimize the order of flags to make them more friendly
  ([#23](https://github.com/windvalley/gossh/issues/23)).

- Password prompt for login user changed from `Password` to `Password for zhangsan`.

- Optimize output error messages that caused by improper use.

### Fixed

- Fix default `completion` command description is inconsistent with others
  ([#22](https://github.com/windvalley/gossh/issues/22)).

## [1.5.0]

### Added

- Add subcommand `vault` that helps you encrypt/decrypt confidential information without compromising security.
  ([#14](https://github.com/windvalley/gossh/issues/14)).

```sh
$ gossh vault -h

Encrypt sensitive content such as passwords so you can protect it rather than
leaving it visible as plaintext in public place. To use vault you need another
password(vault-pass) to encrypt and decrypt the content.

Usage:
  gossh vault [command]

Available Commands:
  decrypt     Decrypt content encrypted by vault
  encrypt     Encrypt sensitive content

Flags:
  -h, --help                     help for vault

Global Flags:
  -V, --auth.vault-pass-file string    file that holds the vault password for encryption and decryption
```

- Add flag `-V/--auth.vault-pass-file` for:
  - Subcommand `vault`: providing vault password to encrypt sensitive content or decrypt content.
  - Decrypting password/passphrase(that encrypted by subcommand `vault`) that provided by `--auth.password`, `--auth.passphrase`, `--auth.pass-file`,
    `--proxy.password`, `--proxy.passphrase`.

### Changed

- Flag `-a/--auth.file string file containing the credentials (format: "username:password")`
  changed to `-a, --auth.pass-file string file that holds the login user's password`.

- Update subcommand `config`: add `auth.vault-pass-file` and optimize some annotations.

- Update `configs/gossh.yaml`.

## [1.4.2]

### Added

- Subcommand `fetch` supports using flag `-s/--run.sudo` to copy files and directories to which the user does not have access permission ([#20](https://github.com/windvalley/gossh/issues/20)).

- Add more examples for subcommand `fetch`.

### Changed

- Update help description for flag `-s/--run.sudo`.

- Update `configs/gossh.yaml`.

## [1.4.1]

### Added

- Add flag `-t/--tmp-dir` for subcommand `fetch`. For details at [#19](https://github.com/windvalley/gossh/issues/19).

## [1.4.0]

### Added

- Add subcommand `fetch` for copying files or dirs from target hosts to local. For details at [#18](https://github.com/windvalley/gossh/issues/18).

### Changed

- Optimize help information. E.g. `remote host(s)` -> `target host(s)`.

## [1.3.1]

### Fixed

- Fix sudo password prompt output not be trimmed as expected ([#15](https://github.com/windvalley/gossh/issues/15)).

- Fix the outputs that were originally `FAILED` are marked as `SUCCESS` ([#16](https://github.com/windvalley/gossh/issues/16)).

### Changed

- Optimize log format. For details at [#17](https://github.com/windvalley/gossh/issues/17).

## [1.3.0]

### Added

- Supports colorful output(that not in json format). For details at [#13](https://github.com/windvalley/gossh/issues/13).

- Add flag `-C/--output.condense` for condensing output and disable colorful.
  It is generally suitable for output to a file to avoid recording color characters(like `^[[35m`).

### Changed

- The log fields order is changed from random to the following order: `level`, `time`, `msg`.

## [1.2.1]

### Fixed

- Fix bug that output in json format by flag `-j/--output.json` not correct [#12](https://github.com/windvalley/gossh/issues/12)

## [1.2.0]

### Added

- Add `$PWD/.gossh.yaml` as the default configuration file with higher priority than `$HOME/.gossh.yaml`.

- Add `-L/--hosts.list` for subcommand `command`,`script`,`push`.
  Just outputs a list of target hosts, and does not do anything else.

### Changed

- Optimized help information.

## [1.1.0]

### Changed

- For ease of understanding, the subcommand `exec` has been renamed to `command`.

- Optimized help examples of subcommand `command`.

## [1.0.3]

### Fixed

- Fix flag `--timeout.command` does not work in some case. For details at ([#7](https://github.com/windvalley/gossh/issues/7)).

### Changed

- Flag `--timeout.command` for subcommand `push` changed to `pushing files/dirs to each remote host` from `pushing each file/dir to each remote host`.

## [1.0.2]

### Fixed

- Subcommand `config`: fix issue [#8](https://github.com/windvalley/gossh/issues/8).

- Fix an issue that sudo command will stuck on remote server when wrong password was provided([#6](https://github.com/windvalley/gossh/issues/6)).

### Changed

- Optimized help information.

- `configs/gossh.yaml`: fixed about issue [#8](https://github.com/windvalley/gossh/issues/8).

## [1.0.1]

### Fixed

- Fix the bug that proxy case is not recognized when connecting to proxy server timeout.

## [1.0.0]

### Added

- Supports SSH Proxy, it can connect to the target hosts by specifying the ssh proxy server.
  Add flags:

  ```text
  -X, --proxy.server string        proxy server address
  --proxy.identity-files strings   identity files for proxy(default the same as 'auth.identity-files')
  --proxy.passphrase string        passphrase of the identity files for proxy(default the same as 'auth.passphrase')
  --proxy.password string          password for proxy(default the same as 'auth.password')
  --proxy.port int                 proxy server port (default 22)
  --proxy.user string              login user for proxy(default the same as 'auth.user')
  ```

- Support parsing identity-files(private keys) with passphrase.
  Add flag `-K/--auth.passphrase` for parsing identity files with passphrase.

- Add flag `-k/--auth.ask-pass` for asking password of login user.

### Changed

- Auto detected supported authentication methods:
  `ssh-agent authentication` -> `pubkey authentication` -> `password from flag/config` -> `username:password from a file`.
  If no legal authentication method is detected, you will be prompted to enter password.

- Add more detailed authentication debug messages(print by flag `-v/--verbose`).

- Subcommand `config` add items: `auth.ask-pass`, `auth.passphrase`, and flags about new feature `proxy`.

- Optimized help examples of subcommand `exec`, `script`.

- Demo config file `configs/gossh.yaml` updated.

### Removed

- Delete flag `-k/--auth.pubkey`.
  Changed to: If the identity files specified by flag `-i/--auth.identity-files` are valid,
  the pubkey authentication method will be used automatically.

### Fixed

- Item `auth.identity-file` of subcommand `config` fixed as `auth.identity-files`.

## [0.9.1]

### Fixed

- Fix the bug that while the host contains blank characters at the beginning and end of the host,
  it will cause the host to fail to resolve.

- Fix the bug that if there is a blank line in the host list file,
  it will cause the client host to be regarded as the target host.

## [0.9.0]

### Added

- Support expanding host pattern that from commandline arguments or from host list file(specified by `-H` flag) to host list, and deduplicate the host list.
  Supported host patterns e.g.:

  ```text
  10.16.0.[1-10]
  foo[01-03].bar.com
  foo[01-03,06,12-16].bar.com
  foo[01-03,06,12-16].[beijing,wuhan].bar.com
  foo[01-03,06,12-16].idc[1-3].[beijing,wuhan].bar.com
  ```

### Changed

Change the identifier of the success or failure of each remote host output result:

`Success` to `SUCCESS` and `Failed` to `FAILED`.

### Fixed

Fix a typo that coz output `elapsed` field not shown in correct way. E.g.:

Fix before:

`level=info msg=success count: 955, failed count: 0, elapsed: 8s time=2021-12-15 22:17:33`

Fix after:

`level=info msg=success count: 936, failed count: 0, elapsed: 5.93s time=2021-12-22 23:17:36`

## [0.8.2]

### Added

- Subcommand `push` supports timeout for pushing each file/dir to each remote host by flag `--timetout.command`.
  This feature solves the problem of the entire `gossh` task stuck if the network of a few remote servers is slow.

- Add more help examples for subcommand `push`, `exec`, `script`.

### Fixed

- Fix the problem that if pushing files/dirs fails, the temporary hidden files are not automatically deleted.

## [0.8.1]

### Fixed

Fix the problem of compression ratio of zip for improving files/dirs transmission efficiency.

## [0.8.0]

### Added

- Subcommand 'push' supports copying directories.
  Also supports push files and directories efficiently at the same time. For efficient transmission, gossh adopts the method of first compressing locally and then decompressing files and directories on the remote server, so the `unzip` command is required on the remote server.

## [0.7.1]

### Changed

Optimize flag `-d/--dest-path` for subcommand `push` and `script`.
If the dest directory given by flag `-d` does not exist or does not have permission to write, output an easy-to-understand error message.

## [0.7.0]

### Added

- Subcommand `push`: keep mode and mtime of dest files and source files the same.

### Security

- For subcommand `push`: For security reasons, if the files to be copied already exists on the target hosts, error messages will be output. If you think it is safe to overwrite the files, you can specify `-F/--force` flag to force overwrite them.

- For subcommand `script`: For security reasons, if the script file already on the target hosts, error messages will
  be output. If you think it is safe to overwrite the script, you can specify `-F/--force` flag to force overwrite it.

## [0.6.1]

### Added

- Subcommand 'push' can push files, not only a file.

## [0.6.0]

### Added

- Provide the subcommand `config` to help users generate configuration file in easy way.

## [0.5.1]

### Added

- Supports three types of ssh tasks.
  `exec`: Execute commands in remote hosts;
  `script`: Execute a local script in remote hosts;
  `push`: Push a local file to remote hosts.

- Supports using sudo to execute the commands or a script as other user(default is `root`).

- Supports specify i18n environment variable value while executing commands or a script to help keep the language of the outputs consistent. For example: zh_CN.UTF-8, en_US.UTF-8.

- Supports four authentication methods.
  Priority: `ssh-agent authentication` -> `pubkey authentication` -> `password from command flag` -> `username:password from a file`.
  If the user is not specified, the system environment variable `$USER` will be used by default.

- Supports two methods to specify target hosts. One is through command line arguments, input one or more target hosts, separated by space. The other is through command line flag or configuration file option to specify the hosts file. Both methods can be used at the same time.

- Supports three kinds of timeout:
  Timeout for connecting each remote host (default `10` seconds);
  Timeout for executing commands or a script on each remote host;
  Timeout for the current gossh task.

- Supports outputting the execution results of ssh to a file or screen or to a file and screen at the same time. Supports specifying the format of output information as json. Supports outputting debug information. Supports silent output.

- High-performance and high-concurrency. You can specify number of concurrent connections (default `1`).

- For ease of use, it supports config file. You can write flags that are not frequently modified into the config file, so you don't need to laboriously specify these flags on the command line. If the flag in both command line and config file, flag that from command line takes precedence over the other. The default config file is: `~/.gossh.yaml`.

### Changed

### Removed

### Fixed

### Security
