package configflags

import (
	"encoding/json"

	"github.com/spf13/pflag"
)

// ConfigFlags is cli flags that also in config file.
type ConfigFlags struct {
	Auth    *Auth    `json:"auth" mapstructure:"auth"`
	Hosts   *Hosts   `json:"hosts" mapstructure:"hosts"`
	Run     *Run     `json:"run" mapstructure:"run"`
	Output  *Output  `json:"output" mapstructure:"output"`
	Timeout *Timeout `json:"timeout" mapstructure:"timeout"`
}

// New config flags.
func New() *ConfigFlags {
	return &ConfigFlags{
		Auth:    NewAuth(),
		Hosts:   NewHosts(),
		Run:     NewRun(),
		Output:  NewOutput(),
		Timeout: NewTimeout(),
	}
}

// AddFlagsTo flagset.
func (c *ConfigFlags) AddFlagsTo(flags *pflag.FlagSet) {
	c.Auth.AddFlagsTo(flags)
	c.Hosts.AddFlagsTo(flags)
	c.Run.AddFlagsTo(flags)
	c.Output.AddFlagsTo(flags)
	c.Timeout.AddFlagsTo(flags)
}

// String ...
func (c *ConfigFlags) String() string {
	data, _ := json.Marshal(c)

	return string(data)
}

// Complete ...
func (c *ConfigFlags) Complete() error {
	if err := c.Auth.Complete(); err != nil {
		return err
	}

	return nil
}

// Validate ...
func (c *ConfigFlags) Validate() (errs []error) {
	errs = append(errs, c.Auth.Validate()...)
	errs = append(errs, c.Hosts.Validate()...)
	errs = append(errs, c.Run.Validate()...)
	errs = append(errs, c.Output.Validate()...)
	errs = append(errs, c.Timeout.Validate()...)

	return
}
