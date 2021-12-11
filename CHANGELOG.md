# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
