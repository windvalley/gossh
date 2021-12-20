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
	flagAuthUser          = "auth.user"
	flagAuthPassword      = "auth.password"
	flagAuthFile          = "auth.file"
	flagAuthPubkey        = "auth.pubkey"
	flagAuthIdentityFiles = "auth.identity-files"
)

// Auth config.
type Auth struct {
	User          string   `json:"user" mapstructure:"user"`
	Password      string   `json:"password" mapstructure:"password"`
	File          string   `json:"file" mapstructure:"file"`
	Pubkey        bool     `json:"pubkey" mapstructure:"pubkey"`
	IdentityFiles []string `json:"identity-files" mapstructure:"identity-files"`
}

// NewAuth ...
func NewAuth() *Auth {
	return &Auth{
		User:          "",
		Password:      "",
		File:          "",
		Pubkey:        false,
		IdentityFiles: []string{},
	}
}

// AddFlagsTo pflagSet.
func (a *Auth) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(&a.User, flagAuthUser, "u", "", "login user (default is $USER)")
	fs.StringVarP(&a.Password, flagAuthPassword, "p", a.Password, "password of the login user")
	fs.StringVarP(&a.File, flagAuthFile, "a", a.File,
		`file containing the credentials (format: "username:password")`)
	fs.BoolVarP(&a.Pubkey, flagAuthPubkey, "k", a.Pubkey, "use pubkey authentication")
	fs.StringSliceVarP(&a.IdentityFiles, flagAuthIdentityFiles, "i", nil,
		"identity files (default is $HOME/.ssh/{id_rsa,id_dsa})")
}

// Complete some flags value.
func (a *Auth) Complete() error {
	if a.User == "" {
		a.User = os.Getenv("USER")
	}

	if len(a.IdentityFiles) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		a.IdentityFiles = []string{
			fmt.Sprintf("%s/.ssh/id_rsa", home),
			fmt.Sprintf("%s/.ssh/id_dsa", home),
		}
	}

	return nil
}

// Validate flags.
func (a *Auth) Validate() (errs []error) {
	if a.File != "" && !util.FileExists(a.File) {
		errs = append(errs, fmt.Errorf("invalid %s: %s not found", flagAuthFile, a.File))
	}

	return
}
