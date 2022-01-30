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

	"github.com/spf13/pflag"
)

const (
	flagRunSudo        = "run.sudo"
	flagRunAsUser      = "run.as-user"
	flagRunLang        = "run.lang"
	flagRunConcurrency = "run.concurrency"
)

// Run ...
type Run struct {
	Sudo        bool   `json:"sudo" mapstructure:"sudo"`
	AsUser      string `json:"as-user" mapstructure:"as-user"`
	Lang        string `json:"lang" mapstructure:"lang"`
	Concurrency int    `json:"concurrency" mapstructure:"concurrency"`
}

// NewRun ...
func NewRun() *Run {
	return &Run{
		Sudo:        false,
		AsUser:      "root",
		Concurrency: 1,
	}
}

// AddFlagsTo ...
func (r *Run) AddFlagsTo(flags *pflag.FlagSet) {
	flags.BoolVarP(&r.Sudo, flagRunSudo, "s", r.Sudo, "use sudo to execute commands/script or fetch files/dirs")
	flags.StringVarP(&r.AsUser, flagRunAsUser, "U", r.AsUser, "run via sudo as this user")
	flags.StringVarP(
		&r.Lang,
		flagRunLang,
		"L",
		r.Lang,
		`specify i18n while executing command (e.g. zh_CN.UTF-8|en_US.UTF-8)`,
	)
	flags.IntVarP(&r.Concurrency, flagRunConcurrency, "c", r.Concurrency,
		"number of concurrent connections")
}

// Complete ...
func (r *Run) Complete() error {
	return nil
}

// Validate ...
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
