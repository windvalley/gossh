/*
Copyright © 2021 windvalley

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

package configflags

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/windvalley/gossh/pkg/util"
)

//nolint:gosec
const (
	flagAuthUser          = "auth.user"
	flagAuthPassword      = "auth.password"
	flagAuthAskPass       = "auth.ask-pass"
	flagAuthPassFile      = "auth.pass-file"
	flagAuthIdentityFiles = "auth.identity-files"
	flagAuthPassphrase    = "auth.passphrase"
	flagAuthVaultPassFile = "auth.vault-pass-file"
)

// Auth config.
type Auth struct {
	User          string   `json:"user" mapstructure:"user"`
	Password      string   `json:"password" mapstructure:"password"`
	AskPass       bool     `json:"ask-pass" mapstructure:"ask-pass"`
	PassFile      string   `json:"pass-file" mapstructure:"pass-file"`
	IdentityFiles []string `json:"identity-files" mapstructure:"identity-files"`
	Passphrase    string   `json:"passphrase" mapstructure:"passphrase"`
	VaultPassFile string   `json:"vault-pass-file" mapstructure:"vault-pass-file"`
}

// NewAuth config.
func NewAuth() *Auth {
	return &Auth{
		User:          "",
		Password:      "",
		AskPass:       false,
		PassFile:      "",
		IdentityFiles: []string{"~/.ssh/id_rsa"},
		Passphrase:    "",
		VaultPassFile: "",
	}
}

// AddFlagsTo pflagSet.
func (a *Auth) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(&a.User, flagAuthUser, "u", a.User, "login user (default $USER)")
	fs.StringVarP(&a.Password, flagAuthPassword, "p", a.Password, "password of login user")
	fs.BoolVarP(&a.AskPass, flagAuthAskPass, "k", a.AskPass, "ask for the password of login user")
	fs.StringVarP(&a.PassFile, flagAuthPassFile, "a", a.PassFile,
		`file that holds the password of login user`)
	fs.StringSliceVarP(&a.IdentityFiles, flagAuthIdentityFiles, "I", a.IdentityFiles,
		"identity files")
	fs.StringVarP(&a.Passphrase, flagAuthPassphrase, "K", a.Passphrase,
		"passphrase of the identity files")
	fs.StringVarP(&a.VaultPassFile, flagAuthVaultPassFile, "V", a.VaultPassFile,
		`text file or executable file that holds the vault password
for encryption and decryption`)
}

// Complete some flags value.
func (a *Auth) Complete() error {
	var err error

	if a.User == "" {
		a.User = os.Getenv("USER")
	}

	if len(a.IdentityFiles) == 0 {
		a.IdentityFiles, err = getDefaultIdentityFiles()
	}

	return err
}

// Validate flags.
func (a *Auth) Validate() (errs []error) {
	if a.PassFile != "" && !util.FileExists(a.PassFile) {
		errs = append(errs, fmt.Errorf("invalid %s: %s not found", flagAuthPassFile, a.PassFile))
	}

	if a.VaultPassFile != "" && !util.FileExists(a.VaultPassFile) {
		errs = append(errs, fmt.Errorf("invalid %s: %s not found", flagAuthVaultPassFile, a.VaultPassFile))
	}

	return
}

func getDefaultIdentityFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	identityFiles := []string{
		fmt.Sprintf("%s/.ssh/id_rsa", home),
	}

	return identityFiles, nil
}
