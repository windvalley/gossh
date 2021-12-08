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
	flags.StringVarP(&o.File, flagOutputFile, "o", o.File, "file to which messages are output")
	flags.BoolVarP(&o.JSON, flagOutputJSON, "j", o.JSON, "output messages in json format")
	flags.BoolVarP(&o.Quiet, flagOutputQuite, "q", o.Quiet,
		"do not output messages to screen (except error messages)")
	flags.BoolVarP(&o.Verbose, flagOutputVerbose, "v", o.Verbose, "show debug messages")
}

// Complete ...
func (o *Output) Complete() error {
	return nil
}

// Validate ...
func (o *Output) Validate() (errs []error) {
	return
}
