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
	"encoding/json"

	"github.com/spf13/pflag"
)

// Config instance.
var Config *ConfigFlags

// ConfigFlags is cli flags that also in config file.
type ConfigFlags struct {
	Auth    *Auth    `json:"auth" mapstructure:"auth"`
	Hosts   *Hosts   `json:"hosts" mapstructure:"hosts"`
	Run     *Run     `json:"run" mapstructure:"run"`
	Output  *Output  `json:"output" mapstructure:"output"`
	Proxy   *Proxy   `json:"proxy" mapstructure:"proxy"`
	Timeout *Timeout `json:"timeout" mapstructure:"timeout"`
}

// New config flags.
func New() *ConfigFlags {
	return &ConfigFlags{
		Auth:    NewAuth(),
		Hosts:   NewHosts(),
		Run:     NewRun(),
		Output:  NewOutput(),
		Proxy:   NewProxy(),
		Timeout: NewTimeout(),
	}
}

// AddFlagsTo flagset.
func (c *ConfigFlags) AddFlagsTo(flags *pflag.FlagSet) {
	c.Auth.AddFlagsTo(flags)
	c.Hosts.AddFlagsTo(flags)
	c.Run.AddFlagsTo(flags)
	c.Output.AddFlagsTo(flags)
	c.Proxy.AddFlagsTo(flags)
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

	if err := c.Proxy.Complete(); err != nil {
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
	errs = append(errs, c.Proxy.Validate()...)

	return
}
