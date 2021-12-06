package configflags

import (
	"fmt"

	"github.com/spf13/pflag"
)

const (
	flagRunSudo        = "run.sudo"
	flagRunAsUser      = "run.as-user"
	flagRunConcurrency = "run.concurrency"
)

// Run ...
type Run struct {
	Sudo        bool   `json:"sudo" mapstructure:"sudo"`
	AsUser      string `json:"as-user" mapstructure:"as-user"`
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
	flags.BoolVarP(&r.Sudo, flagRunSudo, "s", r.Sudo, "use sudo to execute the command")
	flags.StringVarP(&r.AsUser, flagRunAsUser, "U", r.AsUser, "run via sudo as this user")
	flags.IntVarP(&r.Concurrency, flagRunConcurrency, "c", r.Concurrency,
		"number of goroutines to spawn for simultaneous connection attempts")
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
