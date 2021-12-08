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
		"timeout for each ssh connection")
	flags.IntVarP(&t.Command, flagTimeoutCommand, "", t.Command,
		"timeout for executing commands/script on each remote host")
	flags.IntVarP(&t.Task, flagTimeoutTask, "", t.Task, "the overall timeout for this gossh task")
}

// Complete ...
func (t *Timeout) Complete() error {
	return nil
}

// Validate ...
func (t *Timeout) Validate() (errs []error) {
	return
}
