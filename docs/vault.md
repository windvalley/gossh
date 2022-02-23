# Vault

Encrypt sensitive content such as passwords so you can protect it rather than
leaving it visible as plaintext in public place.

To use `vault` you need another password(vault-pass) to encrypt and decrypt the content.

The vault password can be provided by flag `-V, --auth.vault-pass-file`, or from command line prompt.

The value of flag `-V` can be a text file containing plaintext vault password, or a executable file fetching the vault password from restapi or databases or some other security places.

If you don't want to type the flag `-V` every time you run the `gossh vault` command, you can write this flag value to the configuration file.

## Encrypt

Encrypt sensitive content(string).

### Examples

#### demo1

```sh
$ gossh vault encrypt
```

Output:

```text
New Vault password:
Confirm new vault password:
Plaintext:
Confirm plaintext:

GOSSH-AES256:a40ab7109050cd20d06fc8e39412d5e605e7a1a1ecc84ff686fb82b88518dde0
```

`Plaintext` above is the sensitive string to encrypt.

#### demo2

```sh
$ gossh vault encrypt -V ./vault-pass-file
```

Output:

```text
Plaintext:
Confirm plaintext:

GOSSH-AES256:349a1220bc8adbb6b784624e8f4e913b24cf0836c45b73e9ab16c66cec7c3adf
```

### demo3

```sh
$ gossh vault encrypt "the-password" -V ./vault-pass-file
```

Output:

```text
GOSSH-AES256:1ef8a41af6f38046c7eabe5a5221274f084c0f3bf0fdb99c793b7c069139378e
```

## Decrypt

Decrypt content(string) encrypted by `vault`.

### Examples

```sh
$ gossh vault decrypt -V ./vault-pass-file GOSSH-AES256:1ef8a41af6f38046c7eabe5a5221274f084c0f3bf0fdb99c793b7c069139378e
```

Output:

```text
the-password
```

## Encrypt-file

Encrypt a file.

### Examples

```sh
$ gossh vault encrypt-file -V ./vault-pass-file foo.txt
```

Output:

```text
Encryption successful
```

```sh
cat foo.txt
```

Output:

```text
GOSSH-AES256:631c5a5ced3aecc2c34532cdb08339a130b3fe59ccc1154c526c30f452bb92e211277fdad30226d6897f5557700bd00d776f858562e3eff2fa40605fba5f9aa36cc9b33e842e941e1995761a38c8278b
```

## Decrypt-file

Decrypt `vault` encrypted file.

### Examples

```sh
$ gossh vault decrypt-file foo.txt -V ./vault-pass-file
```

Output:

```text
Decryption successful
```

## View

View `vault` encrypted file.

### Examples

```sh
$ gossh vault view foo.txt -V ./vault-pass-file
```

Output:

```text
the sensitive content
...

(END)
```
