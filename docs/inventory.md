# Inventory

Inventory file is a file that stores the target hosts. Inventory file is not present by default.
If you want `gossh` to use inventory file by default, you can specify it by `hosts.inventory` in the configuration file. Otherwise, you must use it by command flag `-H, --hosts.inventory`.

If you don't use an inventory file, you must provide the target hosts as positional arguments, separated by spaces.

## Inventory format

```ini
# This is a hosts inventory file for gossh

# no group hosts
alias_name_node1 host=node1.sre.im
node100.sre.im

# hosts group
[webserver]
# host entry
alias_name_node2 host=192.168.33.12 port=8022 user=vagrant password=123456 keys=~/.ssh/id_dsa,~/.ssh/id_rsa passphrase=xxx
node[06-07].sre.im port=9022 user=lisi password=654321
node08.sre.im

# vars group for hosts group webserver
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

Available variables: `host`, `port`, `user`, `password`, `keys`, `passphrase`.

Host variable priority: `vars from host entry` > `vars group` > `vars from command flags`.

Host patterns will be auto expanded to host list, the supported host patterns demo:

```text
10.16.0.[1-10]
foo[01-03].bar.com
foo[01-03,06,12-16].idc[1-3].[beijing,wuhan].bar.com
```

The following examples used the inventory file above.

## Examples

### Specify inventory file by command flag

```sh
# Get all hosts that in inventory by default.
$ gossh command -H /path/hosts.txt -l
```

Output:

```text
alias_name_node1
node100.sre.im
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im
192.168.1.10

hosts (7)
```

### Specify inventory file in configuration file

Modify `~/.gossh.yaml` or `./.gossh.yaml` as following:

```yaml
hosts:
  # Default inventory file that holds the target hosts.
  # Default: ""
  inventory: "/path/hosts.txt"
```

```sh
# Get all hosts that in inventory by default.
$ gossh command -l
```

Output:

```text
alias_name_node1
node100.sre.im
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im
192.168.1.10

hosts (7)
```

### Filter hosts by host name or hosts group name

```sh
# Filter by group name.
$ gossh command webserver -l
```

Output:

```text
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im

hosts (4)
```

```sh
# Filter by host name.
$ gossh command 192.168.1.10 -l
```

Output:

```text
192.168.1.10

hosts (1)
```

```sh
# Filter by group name and host name
$ gossh command webserver 192.168.1.10 -l
```

Output:

```text
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im
192.168.1.10

hosts (5)
```

### Specify target hosts that not in inventory file

```sh
# Filter by group name and host name, and add other hosts that not in inventory file.
$ gossh command webserver 192.168.1.10 "not-in-inventory-[1-3].sre.im" -l
```

Output:

```text
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im
192.168.1.10
not-in-inventory-1.sre.im
not-in-inventory-2.sre.im
not-in-inventory-3.sre.im

hosts (8)
```

```sh
# Specify target hosts that not in inventory file.
$ gossh command "not-in-inventory[1-3].sre.im" -l
```

Output:

```text
not-in-inventory-1.sre.im
not-in-inventory-2.sre.im
not-in-inventory-3.sre.im

hosts (3)
```

### Deduplicate target hosts

If found duplicate hosts, it will deduplicate them by default.

```sh
$ gossh command webserver "node0[6-7].sre.im" -l
```

Output:

```text
alias_name_node2
node06.sre.im
node07.sre.im
node08.sre.im

hosts (4)
```
