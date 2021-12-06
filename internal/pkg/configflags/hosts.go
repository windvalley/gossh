package configflags

import (
	"fmt"

	"github.com/spf13/pflag"
)

const (
	flagHostsFile = "hosts.file"
	flagHostsPort = "hosts.port"
)

// Hosts ...
type Hosts struct {
	File string `json:"file" mapstructure:"file"`
	Port int    `json:"port" mapstructure:"port"`
}

// NewHosts ...
func NewHosts() *Hosts {
	return &Hosts{
		File: "",
		Port: 22,
	}
}

// AddFlagsTo pflagSet.
func (h *Hosts) AddFlagsTo(fs *pflag.FlagSet) {
	fs.StringVarP(&h.File, flagHostsFile, "H", h.File, "the file containing the hosts that to ssh")
	fs.IntVarP(&h.Port, flagHostsPort, "P", h.Port, "the port to be used when connecting")
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

	return
}
