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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/fatih/color"
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

func init() {
	util.CobraAddSubCommandInOrder(Cmd,
		encryptCmd, decryptCmd, encryptFileCmd, decryptFileCmd, viewCmd)
}

// SetHelpFunc for vault command and its subcommands.
func SetHelpFunc(rootCmd *cobra.Command) {
	markHiddenGlobalFlagsExceptsForVault := func() {
		util.CobraMarkHiddenGlobalFlagsExcept(
			rootCmd,
			"auth.vault-pass-file",
			"output.verbose",
		)
	}

	Cmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().HelpFunc()(command, strings)
	})

	encryptCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().Parent().HelpFunc()(command, strings)
	})

	decryptCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().Parent().HelpFunc()(command, strings)
	})

	encryptFileCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().Parent().HelpFunc()(command, strings)
	})

	decryptFileCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().Parent().HelpFunc()(command, strings)
	})

	viewCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		markHiddenGlobalFlagsExceptsForVault()
		command.Parent().Parent().HelpFunc()(command, strings)
	})
}

func getVaultConfirmPassword() string {
	password := getVaultPasswordFromFile()
	if password != "" {
		return password
	}

	prompt := "New Vault password: "
	password, err := getConfirmPasswordFromPrompt(prompt)
	if err != nil {
		util.CheckErr(fmt.Sprintf("get vault password from terminal prompt failed: %s", err))
	}

	log.Debugf("confirmed vault password that from terminal prompt")

	return password
}

// GetVaultPassword from terminal prompt or vault file.
func GetVaultPassword() string {
	var err error

	password := getVaultPasswordFromFile()
	if password != "" {
		return password
	}

	prompt := "Vault password: "
	for {
		password, err = getPasswordFromPrompt(prompt)
		if err != nil {
			util.CheckErr(fmt.Sprintf("get vault password from terminal prompt '%s' failed: %s", prompt, err))
		}
		if password != "" {
			break
		}

		fmt.Printf("password can not be null, retry\n")
	}

	log.Debugf("read vault password from terminal prompt '%s'", prompt)

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

func getPasswordFromPrompt(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	var passwordByte []byte
	passwordByte, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}

	password := string(passwordByte)

	fmt.Println("")

	return password, nil
}

func getConfirmPasswordFromPrompt(prompt string) (string, error) {
	var (
		password        string
		passwordConfirm string
		err             error
	)

	warnStr := color.YellowString("input can not be null, retry")

	for {
		password, err = getPasswordFromPrompt(prompt)
		if err != nil {
			return "", err
		}
		if password != "" {
			break
		}

		fmt.Println(warnStr)
	}

	for {
		passwordConfirm, err = getPasswordFromPrompt(fmt.Sprintf("Confirm %s", strings.ToLower(prompt)))
		if err != nil {
			return "", err
		}
		if passwordConfirm != "" {
			break
		}

		fmt.Println(warnStr)
	}

	if password != passwordConfirm {
		return "", errors.New("two inputs do not match")
	}

	return password, nil
}
