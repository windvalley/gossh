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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/aes"
	"github.com/windvalley/gossh/pkg/util"
)

var deOutputFile string

// decryptFileCmd represents the vault decrypt-file command
var decryptFileCmd = &cobra.Command{
	Use:   "decrypt-file",
	Short: "Decrypt vault encrypted file",
	Long: `
Decrypt vault encrypted file.`,
	Example: `
    # Decrypt a vault encrypted file by asking for vault password.
    $ gossh vault decrypt-file /path/auth.txt

    # Decrypt a vault encrypted file by vault password file.
    $ gossh vault decrypt-file /path/auth.txt -V /path/vault-password-file

    # Output decrypted content to another file.
    $ gossh vault decrypt-file /path/auth.txt -O /path/plaintxt.txt

    # Output decrypted content to screen.
    $ gossh vault decrypt-file /path/auth.txt -O -`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			util.CobraCheckErrWithHelp(cmd, "requires one arg to represent the vault encrypted file")
		}

		if len(args) > 1 {
			util.CobraCheckErrWithHelp(cmd, "to many args, only need one")
		}

		if !util.FileExists(args[0]) {
			util.CheckErr(fmt.Sprintf("file '%s' not found", args[0]))
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		vaultPass := GetVaultPassword()

		file := args[0]

		p, err := ioutil.ReadFile(file)
		util.CheckErr(err)

		content := string(p)

		if !aes.IsAES256CipherText(content) {
			util.CheckErr(fmt.Sprintf("'%s' is not vault encrypted file", file))
		}

		decryptContent, err := aes.AES256Decode(content, vaultPass)
		if err != nil {
			err = fmt.Errorf("decrypt failed: %w", err)
		}
		util.CheckErr(err)

		var (
			f    *os.File
			err1 error
		)

		if deOutputFile != "" {
			if deOutputFile == "-" {
				fmt.Println(decryptContent)
				fmt.Printf("Decryption successful\n")
				return
			}
			f, err1 = os.OpenFile(deOutputFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
		} else {
			f, err1 = os.OpenFile(file, os.O_TRUNC|os.O_RDWR, os.ModePerm)
		}
		util.CheckErr(err1)

		reader := bytes.NewReader([]byte(decryptContent))
		_, err = reader.WriteTo(f)
		util.CheckErr(err)

		fmt.Printf("\nDecryption successful\n")
	},
}

func init() {
	decryptFileCmd.Flags().StringVarP(
		&deOutputFile,
		"output-file",
		"O",
		"",
		"file that decrypted content is written to (use - for stdout)",
	)
}
