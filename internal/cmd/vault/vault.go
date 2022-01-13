/*
Copyright © 2022 windvalley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

// Cmd represents the vault command
var Cmd = &cobra.Command{
	Use:   "vault",
	Short: "Encryption and decryption utility",
	Long: `
Encrypt sensitive content such as passwords so you can protect it rather than 
leaving it visible as plaintext in public place. To use vault you need another 
password(vault-pass) to encrypt and decrypt the content.`,
}

//func init() {
//persistentFlags := Cmd.PersistentFlags()
//}

func getVaultConfirmPassword() string {
	password := getVaultPasswordFromFile()
	if password != "" {
		return password
	}

	var passwordConfirm string
	for {
		password = getPasswordFromPrompt("New Vault password: ")
		if password != "" {
			break
		}

		fmt.Printf("password can not be null, retry\n")
	}

	for {
		passwordConfirm = getPasswordFromPrompt("Confirm New Vault password: ")
		if passwordConfirm != "" {
			break
		}

		fmt.Printf("password can not be null, retry\n")
	}

	if password != passwordConfirm {
		util.CheckErr("passwords do not match")
	}

	log.Debugf("confirmed vault password that from terminal prompt")

	return password
}

// GetVaultPassword from terminal prompt or vault file.
func GetVaultPassword() string {
	password := getVaultPasswordFromFile()
	if password != "" {
		return password
	}

	for {
		password = getPasswordFromPrompt("Vault password: ")
		if password != "" {
			break
		}

		fmt.Printf("password can not be null, retry\n")
	}

	return password
}

func getVaultPasswordFromFile() string {
	vaultPassFile := configflags.Config.Auth.VaultPassFile
	if vaultPassFile != "" {
		passwordContent, err := ioutil.ReadFile(vaultPassFile)
		if err != nil {
			err = fmt.Errorf("read vault password file '%s' failed: %w", vaultPassFile, err)
		}
		util.CheckErr(err)

		password := strings.TrimSpace(string(passwordContent))

		log.Debugf("read vault password from file '%s'", vaultPassFile)

		return password
	}

	return ""
}

func getPasswordFromPrompt(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)

	var passwordByte []byte
	passwordByte, err := term.ReadPassword(0)
	if err != nil {
		err = fmt.Errorf("get vault password from terminal prompt '%s' failed: %s", prompt, err)
	}
	util.CheckErr(err)

	password := string(passwordByte)

	fmt.Println("")

	log.Debugf("read vault password from terminal prompt '%s'", prompt)

	return password
}
