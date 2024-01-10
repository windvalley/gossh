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

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/aes"
	"github.com/windvalley/gossh/pkg/util"
)

// encryptCmd represents the vault encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt [SENSITIVE-STRING]",
	Short: "Encrypt sensitive content",
	Long: `
Encrypt sensitive content.`,
	Example: `
  Encrypt plaintext by asking for vault password.
  $ gossh vault encrypt "your-sensitive-plaintext"

  Encrypt plaintext by vault password file or script.
  $ gossh vault encrypt "your-sensitive-plaintext" -V /path/vault-password-file-or-script

  Encrypt plaintext from terminal prompt.
  $ gossh vault encrypt -V /path/vault-password-file

  Find more examples at: https://github.com/windvalley/gossh/blob/main/docs/vault.md`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			util.CobraCheckErrWithHelp(cmd, "to many args, only need one")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		vaultPass := getVaultConfirmPassword()

		plainPassword, err := getPlainPassword(args)
		if err != nil {
			err = fmt.Errorf("get plaintext to be encrypted failed: %s", err)
			util.PrintErrExit(err)
		}

		encryptContent, err := aes.AES256Encode(plainPassword, vaultPass)
		if err != nil {
			err = fmt.Errorf("encrypt failed: %w", err)
			util.PrintErrExit(err)
		}

		fmt.Printf("\n%s\n", encryptContent)
	},
}

func getPlainPassword(args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}

	return getConfirmPasswordFromPrompt("Plaintext: ")
}
