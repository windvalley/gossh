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

const (
	flagAuthUser     = "auth.user"
	flagAuthPassword = "auth.password"
	//nolint:gosec
	flagAuthAskPass       = "auth.ask-pass"
	flagAuthFile          = "auth.file"
	flagAuthIdentityFiles = "auth.identity-files"
	flagAuthPassphrase    = "auth.passphrase"
)

// Auth config.
type Auth struct {
	User          string   `json:"user" mapstructure:"user"`
	Password      string   `json:"password" mapstructure:"password"`
	AskPass       bool     `json:"ask-pass" mapstructure:"ask-pass"`
	File          string   `json:"file" mapstructure:"file"`
	IdentityFiles []string `json:"identity-files" mapstructure:"identity-files"`
	Passphrase    string   `json:"passphrase" mapstructure:"passphrase"`
}

// NewAuth ...
func NewAuth() *Auth {
	return &Auth{
		User:          "",
		Password:      "",
		AskPass:       false,
		File:          "",
		IdentityFiles: []string{},
		Passphrase:    "",
	}
}

// AddFlagsTo pflagSet.
func (a *Auth) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(&a.User, flagAuthUser, "u", "", "login user (default is $USER)")
	fs.StringVarP(&a.Password, flagAuthPassword, "p", a.Password, "password of the login user")
	fs.BoolVarP(&a.AskPass, flagAuthAskPass, "k", a.AskPass, "ask for password of login user")
	fs.StringVarP(&a.File, flagAuthFile, "a", a.File,
		`file containing the credentials (format: "username:password")`)
	fs.StringSliceVarP(&a.IdentityFiles, flagAuthIdentityFiles, "i", nil,
		"identity files (default is $HOME/.ssh/{id_rsa,id_dsa})")
	fs.StringVarP(&a.Passphrase, flagAuthPassphrase, "K", a.Passphrase,
		"passphrase of the identity files")
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
	if a.File != "" && !util.FileExists(a.File) {
		errs = append(errs, fmt.Errorf("invalid %s: %s not found", flagAuthFile, a.File))
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
		fmt.Sprintf("%s/.ssh/id_dsa", home),
	}

	return identityFiles, nil
}
