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

import "github.com/spf13/pflag"

const (
	flagOutputFile     = "output.file"
	flagOutputJSON     = "output.json"
	flagOutputCondense = "output.condense"
	flagOutputQuite    = "output.quiet"
	flagOutputVerbose  = "output.verbose"
)

// Output ...
type Output struct {
	File     string `json:"file" mapstructure:"file"`
	JSON     bool   `json:"json" mapstructure:"json"`
	Condense bool   `json:"condense" mapstructure:"condense"`
	Quiet    bool   `json:"quiet" mapstructure:"quiet"`
	Verbose  bool   `json:"verbose" mapstructure:"verbose"`
}

// NewOutput ...
func NewOutput() *Output {
	return &Output{
		File:     "",
		JSON:     false,
		Condense: false,
		Quiet:    false,
		Verbose:  false,
	}
}

// AddFlagsTo flagset.
func (o *Output) AddFlagsTo(flags *pflag.FlagSet) {
	flags.StringVarP(&o.File, flagOutputFile, "o", o.File, "file to which messages are output")
	flags.BoolVarP(&o.JSON, flagOutputJSON, "j", o.JSON, "output messages in json format")
	flags.BoolVarP(&o.Condense, flagOutputCondense, "C", o.Condense, "condense output and disable color")
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
