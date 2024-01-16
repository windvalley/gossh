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
	"strings"

	"github.com/spf13/pflag"
)

const (
	flagRunSudo             = "run.sudo"
	flagRunAsUser           = "run.as-user"
	flagRunLang             = "run.lang"
	flagRunConcurrency      = "run.concurrency"
	flagRunCommandBlacklist = "run.command-blacklist"
)

type Run struct {
	Sudo             bool     `json:"sudo" mapstructure:"sudo"`
	AsUser           string   `json:"as-user" mapstructure:"as-user"`
	Lang             string   `json:"lang" mapstructure:"lang"`
	Concurrency      int      `json:"concurrency" mapstructure:"concurrency"`
	CommandBlacklist []string `json:"command-blacklist" mapstructure:"command-blacklist"`
}

func NewRun() *Run {
	return &Run{
		Sudo:        false,
		AsUser:      "root",
		Concurrency: 1,
	}
}

func (r *Run) AddFlagsTo(flags *pflag.FlagSet) {
	flags.BoolVarP(&r.Sudo, flagRunSudo, "s", r.Sudo, "use sudo to execute commands/script or fetch files/dirs")
	flags.StringVarP(&r.AsUser, flagRunAsUser, "U", r.AsUser, "run via sudo as this user")
	flags.StringVarP(
		&r.Lang,
		flagRunLang,
		"L",
		r.Lang,
		`specify i18n while executing command
(e.g. zh_CN.UTF-8|en_US.UTF-8)`,
	)
	flags.IntVarP(&r.Concurrency, flagRunConcurrency, "c", r.Concurrency,
		"number of concurrent connections")
	flags.StringSliceVarP(
		&r.CommandBlacklist,
		flagRunCommandBlacklist,
		"B",
		r.CommandBlacklist,
		`commands that are prohibited from execution on target hosts
(default: [rm,reboot,halt,shutdown,init,mkfs,mkfs.*,umount,dd])`,
	)
}

func (r *Run) Complete() error {
	newSlice := make([]string, 0)
	for _, s := range r.CommandBlacklist {
		item := strings.TrimSpace(s)
		if item != "" {
			newSlice = append(newSlice, item)
		}
	}

	r.CommandBlacklist = newSlice

	return nil
}

func (r *Run) Validate() (errs []error) {
	if r.Concurrency < 1 {
		errs = append(errs, fmt.Errorf(
			"invalid %s: %d - must be gather than 0",
			flagRunConcurrency,
			r.Concurrency,
		))
	}

	return
}
