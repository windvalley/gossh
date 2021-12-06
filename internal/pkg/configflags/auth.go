package configflags

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
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
	fs.StringVarP(&a.User, flagAuthUser, "u", "", "specify the login user (default is $USER)")
	fs.StringVarP(&a.Password, flagAuthPassword, "p", a.Password, "password of the login user")
	fs.StringVarP(&a.File, flagAuthFile, "a", a.File,
		`file containing the credentials (format is "username:password")`)
	fs.BoolVarP(&a.Pubkey, flagAuthPubkey, "k", a.Pubkey, "use pubkey auth or not")
	fs.StringSliceVarP(&a.IdentityFiles, flagAuthIdentityFiles, "i", nil,
		"specify the identity files (default is $HOME/.ssh/{id_rsa,id_dsa})")
}

// Complete ...
func (a *Auth) Complete() error {
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

// Validate ...
func (a *Auth) Validate() (errs []error) {
	return
}
