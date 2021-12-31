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
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	flagProxyServer        = "proxy.server"
	flagProxyPort          = "proxy.port"
	flagProxyUser          = "proxy.user"
	flagProxyPassword      = "proxy.password"
	flagProxyIdentityFiles = "proxy.identity-files"
	flagProxyPassphrase    = "proxy.passphrase"
)

// Proxy config.
type Proxy struct {
	Server        string   `json:"server" mapstructure:"server"`
	Port          int      `json:"port" mapstructure:"port"`
	User          string   `json:"user" mapstructure:"user"`
	Password      string   `json:"password" mapstructure:"password"`
	IdentityFiles []string `json:"identity-files" mapstructure:"identity-files"`
	Passphrase    string   `json:"passphrase" mapstructure:"passphrase"`
}

// NewProxy ...
func NewProxy() *Proxy {
	return &Proxy{
		Server:        "",
		Port:          22,
		User:          "",
		Password:      "",
		IdentityFiles: []string{},
		Passphrase:    "",
	}
}

// AddFlagsTo pflagSet.
func (p *Proxy) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(&p.Server, flagProxyServer, "X", p.Server, "proxy server address")
	fs.IntVarP(&p.Port, flagProxyPort, "", p.Port, "proxy server port")
	fs.StringVarP(&p.User, flagProxyUser, "", p.User,
		"login user for proxy (default same as 'auth.user')")
	fs.StringVarP(&p.Password, flagProxyPassword, "", p.Password,
		"password for proxy (default same as 'auth.password')")
	fs.StringSliceVarP(&p.IdentityFiles, flagProxyIdentityFiles, "", p.IdentityFiles,
		"identity files for proxy (default same as 'auth.identity-files')")
	fs.StringVarP(&p.Passphrase, flagProxyPassphrase, "", p.Passphrase,
		`passphrase of the identity files for proxy
(default same as 'auth.passphrase')`)
}

// Complete some flags value.
func (p *Proxy) Complete() error {
	var err error

	if p.Server != "" {
		if p.User == "" {
			user := viper.GetString("auth.user")
			if user == "" {
				p.User = os.Getenv("USER")
			} else {
				p.User = user
			}
		}

		if p.Password == "" {
			p.Password = viper.GetString("auth.password")
		}

		if len(p.IdentityFiles) == 0 {
			authIdentityFiles := viper.GetStringSlice("auth.identity-files")
			if len(authIdentityFiles) == 0 {
				p.IdentityFiles, err = getDefaultIdentityFiles()
			} else {
				p.IdentityFiles = authIdentityFiles
			}
		}

		if p.Passphrase == "" {
			p.Passphrase = viper.GetString("auth.passphrase")
		}
	}

	return err
}

// Validate flags.
func (p *Proxy) Validate() (errs []error) {
	return
}
