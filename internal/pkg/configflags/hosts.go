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

	"github.com/windvalley/gossh/pkg/util"
)

const (
	flagHostsFile = "hosts.inventory"
	flagHostsPort = "hosts.port"
	flagHostsList = "hosts.list"
)

// Hosts ...
type Hosts struct {
	Inventory string `json:"inventory" mapstructure:"inventory"`
	Port      int    `json:"port" mapstructure:"port"`
	List      bool   `json:"list" mapstructure:"list"`
}

// NewHosts ...
func NewHosts() *Hosts {
	return &Hosts{
		Inventory: "",
		Port:      22,
		List:      false,
	}
}

// AddFlagsTo pflagSet.
func (h *Hosts) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(
		&h.Inventory,
		flagHostsFile,
		"i",
		h.Inventory,
		`file that holds the target hosts`,
	)
	fs.IntVarP(
		&h.Port,
		flagHostsPort,
		"P",
		h.Port,
		"port of the target hosts",
	)
	fs.BoolVarP(
		&h.List,
		flagHostsList,
		"l",
		h.List,
		"outputs a list of target hosts, and does not do anything else",
	)
}

// Complete ...
func (h *Hosts) Complete() error {
	return nil
}

// Validate ...
func (h *Hosts) Validate() (errs []error) {
	if h.Port < 1 || h.Port > 65535 {
		errs = append(errs, fmt.Errorf(
			"invalid %s: %d - port must be between 0 and 65535",
			flagHostsPort,
			h.Port,
		))
	}

	if h.Inventory != "" && !util.FileExists(h.Inventory) {
		errs = append(errs, fmt.Errorf("invalid %s: %s not found", flagHostsFile, h.Inventory))
	}

	return
}
