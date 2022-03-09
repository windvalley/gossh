# Authentication

`Gossh` supports three SSH authentication methods: `SSH-Agent`, `Pubkey`, `Password`.

It will auto detect above three authentication methods for the login user. The default login user is `$USER`, if it is not specified.

`Password` can be from variable `password` that in inventory file, or from flag `-k/--auth.ask-pass`,`-p/--auth.password`,`-a/--auth.pass-file`, or from relative items in configuration file.

`Pubkey Authentication` is enabled by default through identity files(default `$HOME/.ssh/{id_rsa,id_dsa}` if not specified). The identity files with passphrase are also supported, you can use flag `-K, --auth.passphrase` to specify it.

If the system environment variable `$SSH_AUTH_SOCK` exists, `SSH-Agent Authentication` will be auto enabled.

If the three authentication methods are valid at the same time, the priority order is: `SSH-Agent` > `Pubkey` > `Password`.

## Examples

### Use Password Authentication

```sh
# Ask for password.
$ gossh command target_host -e "uptime" -k

# Give plain password by flag '-p'.
$ gossh command target_host -e "uptime" -p "the-plain-password"

# Give cipher password encrypted by `gossh vault encrypt`.
$ gossh command target_host -e "uptime" -p "the-cipher-password" -V /path/vault-pass-file

# Give password by a password-file.
$ gossh command target_host -e "uptime" -a /path/password-file

# The password was setted in the configuration file(auth.password/auth.file).
$ gossh command target_host -e "uptime"
```

### Use Pubkey Authentication with no passphrase

```sh
# generate rsa or dsa
$ ssh-keygen -t dsa -f /path/id_rsa -N ""

# copy pubkey to target host
$ ssh-copy-id -i /path/id_rsa target_host

# If /path/id_rsa is '~/.ssh/id_rsa', the flag '-I /path/id_rsa' can be omitted.
$ gossh command target_host -e "uptime" -I /path/id_rsa
```

### Use Pubkey Authentication with passphrase

```sh
# generate rsa or dsa
$ ssh-keygen -t dsa -f /path/id_rsa -N "the-passphrase"

# copy pubkey to target host
$ ssh-copy-id -i /path/id_rsa target_host

# If /path/id_rsa is '~/.ssh/id_rsa', the flag '-I /path/id_rsa' can be omitted.
# NOTE: "the-passphrase" can be encrypted by command `gossh vault encrypt`,
# then you must add another flag `-V /paht/vault-pass-file`.
$ gossh command target_host -e "uptime" -I /path/id_rsa -K "the-passphrase"
```

### Use SSH-Agent Authentication

The following steps based on the above steps.

```sh
$ ssh-agent
```

Output:

```text
SSH_AUTH_SOCK=/var/folders/42/nh6v60h917x69c1mtczc_g300000gn/T//ssh-9VvFRZMFXiJc/agent.53250; export SSH_AUTH_SOCK;
SSH_AGENT_PID=53251; export SSH_AGENT_PID;
echo Agent pid 53251;
```

```sh
# export variables
$ SSH_AUTH_SOCK=/var/folders/42/nh6v60h917x69c1mtczc_g300000gn/T//ssh-9VvFRZMFXiJc/agent.53250; export SSH_AUTH_SOCK;
$ SSH_AGENT_PID=53251; export SSH_AGENT_PID;

# Lists fingerprints of all identities currently represented by the agent.
$ ssh-add -l

# Add identity file to ssh-agent.
$ ssh-add ~/.ssh/id_rsa

# Lists fingerprints of all identities currently represented by the agent.
$ ssh-add -l
```

```sh
# Test
$ gossh command target_host -e "uptime" -v
```

### Check which auth method was used to connect the target host

```sh
# login target host
$ ssh target_host

# on the target host
$ tail -f /var/log/secure
```
