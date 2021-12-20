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
	flagTimeoutConn    = "timeout.conn"
	flagTimeoutCommand = "timeout.command"
	flagTimeoutTask    = "timeout.task"
)

// Timeout ...
type Timeout struct {
	Conn    int `json:"conn" mapstructure:"conn"`
	Command int `json:"command" mapstructure:"command"`
	Task    int `json:"task" mapstructure:"task"`
}

// NewTimeout ...
func NewTimeout() *Timeout {
	return &Timeout{
		Conn:    10,
		Command: 0,
		Task:    0,
	}
}

// AddFlagsTo ...
func (t *Timeout) AddFlagsTo(flags *pflag.FlagSet) {
	flags.IntVarP(&t.Conn, flagTimeoutConn, "", t.Conn,
		"timeout for connecting each remote host")
	flags.IntVarP(&t.Command, flagTimeoutCommand, "", t.Command,
		"timeout for executing commands/script on each remote host")
	flags.IntVarP(&t.Task, flagTimeoutTask, "", t.Task, "timeout for the current gossh task")
}

// Complete ...
func (t *Timeout) Complete() error {
	return nil
}

// Validate ...
func (t *Timeout) Validate() (errs []error) {
	return
}
