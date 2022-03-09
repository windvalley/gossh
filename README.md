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

Gossh is a high-performance and high-concurrency ssh tool written in Go.
It can efficiently manage tens of thousands of Linux server clusters.
It is 10 times faster than `Ansible`.
If you need much more performance and better ease of use, you will love `gossh`.

Feel free to open a new issue if you have any issues, questions or suggestions about this project.

## 💝 Features

- Four kinds of ssh tasks:  
  `command`: Execute commands on target hosts.  
  `script`: Execute a local shell script on target hosts.  
  `push`: Copy local files and dirs to target hosts.  
  `fetch`: Copy files and dirs from target hosts to local.

- Auto detect following authentication methods for the login user(default `$USER`):  
  `Password`: from inventory file, or from flag `-k/--auth.ask-pass`,`-p/--auth.password`,`-a/--auth.pass-file`, or from configuration file.  
  `Pubkey Authentication`: by identity files(default `$HOME/.ssh/{id_rsa,id_dsa}`), also include that with passphrase.  
  `SSH-Agent Authentication`: through the system environment variable `$SSH_AUTH_SOCK`.  
  If the above three authentication methods are valid at the same time, the priority order is: `SSH-Agent` > `Pubkey` > `Password`.

- Provide the target hosts by:  
  Hosts/host-patterns/host-group-names as positional arguments separated by space.  
  Inventory file by flag `-i/--hosts.inventory` or from configuration file.

- Expand host patterns that from positional arguments or a inventory file to host list.
  Supported host patterns e.g.:

  ```text
  10.16.0.[1-10]
  foo[01-03].bar.com
  foo[01-03,06,12-16].idc[1-3].[beijing,wuhan].bar.com
  ```

- Allow adding variables to inventory file.  
  Available variables: `host`, `port`, `user`, `password`, `keys`, `passphrase`. E.g.:

  ```text
  alias_name_node1 host=node1.sre.im
  alias_name_node2 host=192.168.33.12 port=8022 user=vagrant password=123456 keys=~/.ssh/id_dsa,~/.ssh/id_rsa passphrase=xxx
  node3.sre.im user=vagrant password=GOSSH-AES256:9cfe499133b69a6c7fc62b5b6ba72d3d8dfb4d0e7987170a40c5d50bb5d71e19
  ```

- Group hosts in inventory file. E.g.:

  ```text
  # no group hosts
  node1.sre.im

  # group hosts
  [webserver]
  node2.sre.im port=6022
  node3.sre.im

  # host variables for group webserver
  [webserver:vars]
  port=8022
  user=zhangsan
  password=plaintextOrCiphertextByVault

  [dbserver]
  db[1-3].sre.im

  # group project1 has hosts that from both group webserver and dbserver
  [project1:children]
  webserver
  dbserver
  ```

- Use `sudo` to run as other user(default `root`) to execute the commands/shell-script or fetch files/dirs.

- Specify i18n environment variable value while executing commands or a shell script to help keep the language of the outputs consistent. For example: `zh_CN.UTF-8`, `en_US.UTF-8`.

- Three kinds of timeout in seconds:  
  Connecting to each target host (default `10`).  
  Subcommand `command`, `script`, `push`, `fetch` for each target host.  
  The entire `gossh` task.

- Output to a file or screen or a file and screen at the same time.  
  Colorful output, json format output, verbose(debug) output, and silent output.

- High-performance and high-concurrency. Customize the number of concurrent connections (default `1`).

- SSH Proxy can be specified to connect to the target hosts.

- Provides subcommand `vault` to encrypt/decrypt confidential information
  such as password or passphrase without compromising security.

- For ease of use, it supports config file. You can write flags that are not frequently changed into the config file, so you don't need to laboriously specify these flags on the command line. If the flag in both command line and config file, flag that from command line takes precedence over the other.  
  The default config file is `$PWD/.gossh.yaml` or `$HOME/.gossh.yaml`, and `$PWD/.gossh.yaml` has a higher priority. Note that the config file is optional, that is, there can be no config file.

- Provides subcommand `config` to help generate configuration file in easy way.

## 🛠 Installation

Prebuilt binaries for macOS and Linux can be downloaded from the [GitHub releases page](https://github.com/windvalley/gossh/releases).

Also you can install `gossh` by compiling:

```sh
$ git clone --depth 1 https://github.com/windvalley/gossh

$ cd gossh

# Note: need to install Go environment first.
$ make && make install
```

## 📜 Usage

```text
$ gossh -h

Gossh is a high-performance and high-concurrency ssh tool.
It can efficiently manage tens of thousands of Linux server clusters.

Find more information at: https://github.com/windvalley/gossh

Usage:
  gossh [command]

Available Commands:
  command     Execute commands on target hosts
  script      Execute a local shell script on target hosts
  push        Copy local files and dirs to target hosts
  fetch       Copy files and dirs from target hosts to local
  play        Runs gossh playbooks
  vault       Encryption and decryption utility
  config      Generate gossh configuration file
  version     Show gossh version information
  help        Help about any command
  completion  Generate the autocompletion script for the specified shell

Flags:
  -u, --auth.user string               login user (default $USER)
  -p, --auth.password string           password of login user
  -k, --auth.ask-pass                  ask for the password of login user
  -a, --auth.pass-file string          file that holds the password of login user
  -I, --auth.identity-files strings    identity files (default $HOME/.ssh/{id_rsa,id_dsa})
  -K, --auth.passphrase string         passphrase of the identity files
  -V, --auth.vault-pass-file string    text file or executable file that holds the vault password
                                       for encryption and decryption
  -i, --hosts.inventory string         file that holds the target hosts
  -P, --hosts.port int                 port of the target hosts (default 22)
  -l, --hosts.list                     outputs a list of target hosts, and does not do anything else
  -s, --run.sudo                       use sudo to execute commands/script or fetch files/dirs
  -U, --run.as-user string             run via sudo as this user (default "root")
  -L, --run.lang string                specify i18n while executing command
                                       (e.g. zh_CN.UTF-8|en_US.UTF-8)
  -c, --run.concurrency int            number of concurrent connections (default 1)
  -o, --output.file string             file to which messages are output
  -j, --output.json                    output messages in json format
  -C, --output.condense                condense output and disable color
  -q, --output.quiet                   do not output messages to screen (except error messages)
  -v, --output.verbose                 show debug messages
  -X, --proxy.server string            proxy server address
      --proxy.port int                 proxy server port (default 22)
      --proxy.user string              login user for proxy (default same as 'auth.user')
      --proxy.password string          password for proxy (default same as 'auth.password')
      --proxy.identity-files strings   identity files for proxy (default same as 'auth.identity-files')
      --proxy.passphrase string        passphrase of the identity files for proxy
                                       (default same as 'auth.passphrase')
      --timeout.task int               timeout seconds for the entire gossh task
      --timeout.conn int               timeout seconds for connecting each target host (default 10)
      --timeout.command int            timeout seconds for handling each target host
      --config string                  config file (default {$PWD,$HOME}/.gossh.yaml)
  -h, --help                           help for gossh

Use "gossh [command] --help" for more information about a command.
```

## 🚀 Performance

Client server: `4vCPUs` and `8GiB`

Target servers: `hosts.list` contains `936` servers distributed in `86` different IDCs across the country.

**Ansible:**

```sh
$ time ansible all -i hosts.list -m command -a "uptime" -f 100 -k
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
$ time gossh command -i hosts.list -e "uptime" -c 100 -k
```

Output:

```text
...

[INFO] 2021-12-22 23:06:50.837228 success count: 936, failed count: 0, elapsed: 6.30s

real    0m6.316s
user    0m13.529s
sys     0m0.592s
```

## 📄 Documentation

- [Configuration](docs/config.md)
- [Inventory](docs/inventory.md)
- [Authentication](docs/authentication.md)
- [Command](docs/command.md)
- [Script](docs/script.md)
- [Push](docs/push.md)
- [Fetch](docs/fetch.md)
- [Vault](docs/vault.md)

## 📝 Changelog

[CHANGELOG](CHANGELOG.md)

## ✨ Contributing

I actively welcome your pull requests, please follow the steps below:

1. Open a new issue at [gossh/issues](https://github.com/windvalley/gossh/issues).

2. Fork the repo and create your branch from `main`.

3. Do the changes in your fork.

4. Send a pull request.

> Note: Any contributions you make will be under the [MIT](LICENSE) Software License.

## ⚖️ License

This project is under the MIT License.
See the [LICENSE](LICENSE) file for the full license text.
