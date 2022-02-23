# Command

Execute shell commands on target hosts.

## Examples

```sh
# Use sudo as user 'zhangsan' to execute commands on target hosts.
$ gossh command host[1-3] -e "uptime" -s -U zhangsan

# Set timeout seconds for executing commands on each target host.
$ gossh command host[1-3] -e "uptime" --timeout.command 10

# Connect target hosts by proxy server 10.16.0.1.
$ gossh command host[1-3] -e "uptime" -X 10.16.0.1

# Specify concurrency connections.
$ gossh command host[1-3] -e "uptime" -c 10
```
