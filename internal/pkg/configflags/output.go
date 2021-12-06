package configflags

import "github.com/spf13/pflag"

const (
	flagOutputFile    = "output.file"
	flagOutputJSON    = "output.json"
	flagOutputQuite   = "output.quiet"
	flagOutputVerbose = "output.verbose"
)

// Output ...
type Output struct {
	File    string `json:"file" mapstructure:"file"`
	JSON    bool   `json:"json" mapstructure:"json"`
	Quiet   bool   `json:"quiet" mapstructure:"quiet"`
	Verbose bool   `json:"verbose" mapstructure:"verbose"`
}

// NewOutput ...
func NewOutput() *Output {
	return &Output{
		File:    "",
		JSON:    false,
		Quiet:   false,
		Verbose: false,
	}
}

// AddFlagsTo flagset.
func (o *Output) AddFlagsTo(flags *pflag.FlagSet) {
	flags.StringVarP(&o.File, flagOutputFile, "o", o.File, "the file where the results will be saved")
	flags.BoolVarP(&o.JSON, flagOutputJSON, "j", o.JSON, "outputs format is json or not")
	flags.BoolVarP(&o.Quiet, flagOutputQuite, "q", o.Quiet,
		"do not print messages to stdout (only print errors)")
	flags.BoolVarP(&o.Verbose, flagOutputVerbose, "v", o.Verbose, "print debug information or not")
}

// Complete ...
func (o *Output) Complete() error {
	return nil
}

// Validate ...
func (o *Output) Validate() (errs []error) {
	return
}
