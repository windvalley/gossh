package configflags

import (
	"github.com/spf13/pflag"
)

// flags
const (
	flagAuthUser         = "auth.user"
	flagAuthPassword     = "auth.password"
	flagAuthFile         = "auth.file"
	flagAuthPubkey       = "auth.pubkey"
	flagAuthIdentityFile = "auth.identity-file"

	flagHostsFile = "hosts.file"
	flagHostsPort = "hosts.port"

	flagRunSudo        = "run.sudo"
	flagRunAsUser      = "run.as-user"
	flagRunConcurrency = "run.concurrency"

	flagOutputFile    = "output.file"
	flagOutputJSON    = "output.json"
	flagOutputQuite   = "output.quiet"
	flagOutputVerbose = "output.verbose"

	flagTimeoutConn    = "timeout.conn"
	flagTimeoutCommand = "timeout.command"
	flagTimeoutTask    = "timeout.task"
)

const (
	defaultSSHPort        = 22
	defaultSSHConnTimeout = 10
)

// ConfigFlags is cli flags that also in config file.
type ConfigFlags struct {
	AuthUser         string
	AuthPassword     string
	AuthFile         string
	AuthPubkey       bool
	AuthIdentityFile string

	HostsFile string
	HostsPort int

	RunSudo        bool
	RunAsUser      string
	RunConcurrency int

	OutputFile    string
	OutputJSON    bool
	OutputQuiet   bool
	OutputVerbose bool

	TimeoutConn    int
	TimeoutCommand int
	TimeoutTask    int
}

// New config flags.
func New() *ConfigFlags {
	return &ConfigFlags{
		AuthUser:         "",
		AuthPassword:     "",
		AuthFile:         "",
		AuthPubkey:       false,
		AuthIdentityFile: "",

		HostsFile: "",
		HostsPort: defaultSSHPort,

		RunSudo:        false,
		RunAsUser:      "root",
		RunConcurrency: 1,

		OutputFile:    "",
		OutputJSON:    false,
		OutputQuiet:   false,
		OutputVerbose: false,

		TimeoutConn:    defaultSSHConnTimeout,
		TimeoutCommand: 0,
		TimeoutTask:    0,
	}
}

// AddFlagsTo flagset.
func (c *ConfigFlags) AddFlagsTo(flags *pflag.FlagSet) {
	flags.StringVarP(&c.AuthUser, flagAuthUser, "u", "", "specify the login user (default is $USER)")
	flags.StringVarP(&c.AuthPassword, flagAuthPassword, "p", c.AuthPassword, "password of the login user")
	flags.StringVarP(&c.AuthFile, flagAuthFile, "a", c.AuthFile,
		`file containing the credentials (format is "username:password")`)
	flags.BoolVarP(&c.AuthPubkey, flagAuthPubkey, "k", c.AuthPubkey, "use pubkey auth or not")
	flags.StringVarP(&c.AuthIdentityFile, flagAuthIdentityFile, "i", "",
		"specify the identity files (default is $HOME/.ssh/{id_rsa,id_dsa})")

	flags.StringVarP(&c.HostsFile, flagHostsFile, "H", c.HostsFile, "the file containing the hosts that to ssh")
	flags.IntVarP(&c.HostsPort, flagHostsPort, "P", c.HostsPort, "the port to be used when connecting")

	flags.BoolVarP(&c.RunSudo, flagRunSudo, "s", c.RunSudo, "use sudo to execute the command")
	flags.StringVarP(&c.RunAsUser, flagRunAsUser, "U", c.RunAsUser, "run via sudo as this user")
	flags.IntVarP(&c.RunConcurrency, flagRunConcurrency, "c", c.RunConcurrency,
		"number of goroutines to spawn for simultaneous connection attempts")

	flags.StringVarP(&c.OutputFile, flagOutputFile, "o", c.OutputFile, "the file where the results will be saved")
	flags.BoolVarP(&c.OutputJSON, flagOutputJSON, "j", c.OutputJSON, "outputs format is json or not")
	flags.BoolVarP(&c.OutputQuiet, flagOutputQuite, "q", c.OutputQuiet,
		"do not print messages to stdout (only print errors)")
	flags.BoolVarP(&c.OutputVerbose, flagOutputVerbose, "v", c.OutputVerbose, "print debug information or not")

	flags.IntVarP(&c.TimeoutConn, flagTimeoutConn, "", c.TimeoutConn,
		"connection timeout for each ssh connection")
	flags.IntVarP(&c.TimeoutCommand, flagTimeoutCommand, "", c.TimeoutCommand,
		"timeout for the command executing on each remote host")
	flags.IntVarP(&c.TimeoutTask, flagTimeoutTask, "", c.TimeoutTask, "timeout for all ssh connections")
}
