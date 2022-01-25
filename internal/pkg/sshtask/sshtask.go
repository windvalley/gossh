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

package sshtask

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ScaleFT/sshkeys"
	"github.com/go-project-pkg/expandhost"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/windvalley/gossh/internal/cmd/vault"
	"github.com/windvalley/gossh/internal/pkg/aes"
	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/batchssh"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

var (
	linuxUserRegex  = "[a-zA-Z0-9_.-]+[$]?"
	sudoPromptRegex = fmt.Sprintf(
		`(?s).*\[sudo\] password for %s: \n|(?s).*\[sudo\] %s 的密码：\n`,
		linuxUserRegex,
		linuxUserRegex,
	)
)

// TaskType ...
type TaskType int

// ...
const (
	CommandTask TaskType = iota
	ScriptTask
	PushTask
	FetchTask
)

type hostVarType int

const (
	hostVarHost hostVarType = iota
	hostVarPort
	hostVarUser
	hostVarPassword
	hostVarKeys
	hostVarPassphrase
)

var hostVarsMap = map[hostVarType]string{
	hostVarHost:       "host",
	hostVarPort:       "port",
	hostVarUser:       "user",
	hostVarPassword:   "password",
	hostVarKeys:       "keys",
	hostVarPassphrase: "passphrase",
}

// taskResult ...
type taskResult struct {
	taskID            string
	hostsSuccessCount int
	hostsFailureCount int
	elapsed           float64
}

// detailResult each ssh host result.
type detailResult struct {
	taskID   string
	hostname string
	status   string
	output   string
}

type pushFiles struct {
	files    []string
	zipFiles []string
}

// Task ...
type Task struct {
	configFlags *configflags.ConfigFlags

	id       string
	taskType TaskType

	sshClient            *batchssh.Client
	sshAgent             net.Conn
	defaultUser          string
	defaultPass          *string
	defaultIdentityFiles []string

	// hostnames or ips from command line arguments.
	hosts []string

	command    string
	scriptFile string

	pushFiles      *pushFiles
	fetchFiles     []string
	dstDir         string
	tmpDir         string
	remove         bool
	allowOverwrite bool

	taskOutput   chan taskResult
	detailOutput chan detailResult

	err error
}

// NewTask ...
func NewTask(taskType TaskType, configFlags *configflags.ConfigFlags) *Task {
	defaultIdentityFiles := parseItentityFiles(configFlags.Auth.IdentityFiles)

	defaultPass := getDefaultPassword(configFlags.Auth)

	return &Task{
		configFlags:          configFlags,
		id:                   time.Now().Format("20060102150405"),
		taskType:             taskType,
		defaultUser:          configFlags.Auth.User,
		defaultPass:          &defaultPass,
		defaultIdentityFiles: defaultIdentityFiles,
		taskOutput:           make(chan taskResult, 1),
		detailOutput:         make(chan detailResult),
	}
}

// Start task.
func (t *Task) Start() {
	if t.sshAgent != nil {
		defer t.sshAgent.Close()
	}

	go func() {
		defer close(t.taskOutput)
		defer close(t.detailOutput)
		t.BatchRun()
	}()

	taskTimeout := t.configFlags.Timeout.Task
	if taskTimeout > 0 {
		go func() {
			time.Sleep(time.Duration(taskTimeout) * time.Second)
			log.Warnf(
				"task timeout, taskID: %s, timeout value: %d seconds",
				t.id,
				taskTimeout,
			)
			close(t.detailOutput)
			close(t.taskOutput)
		}()
	}

	t.HandleOutput()
}

// SetTargetHosts ...
func (t *Task) SetTargetHosts(hosts []string) {
	t.hosts = hosts
}

// SetCommand ...
func (t *Task) SetCommand(command string) {
	t.command = command
}

// SetScriptFile ...
func (t *Task) SetScriptFile(sciptFile string) {
	t.scriptFile = sciptFile
}

// SetPushfiles ...
func (t *Task) SetPushfiles(files, zipFiles []string) {
	t.pushFiles = &pushFiles{
		files:    files,
		zipFiles: zipFiles,
	}
}

// SetFetchFiles ...
func (t *Task) SetFetchFiles(files []string) {
	t.fetchFiles = files
}

// SetScriptOptions ...
func (t *Task) SetScriptOptions(destPath string, remove, allowOverwrite bool) {
	t.dstDir = destPath
	t.remove = remove
	t.allowOverwrite = allowOverwrite
}

// SetPushOptions ...
func (t *Task) SetPushOptions(destPath string, allowOverwrite bool) {
	t.dstDir = destPath
	t.allowOverwrite = allowOverwrite
}

// SetFetchOptions ...
func (t *Task) SetFetchOptions(destPath, tmpDir string) {
	t.dstDir = destPath
	t.tmpDir = tmpDir
}

// RunSSH implements batchssh.Task
func (t *Task) RunSSH(host *batchssh.Host) (string, error) {
	lang := t.configFlags.Run.Lang
	runAs := t.configFlags.Run.AsUser
	sudo := t.configFlags.Run.Sudo

	switch t.taskType {
	case CommandTask:
		return t.sshClient.ExecuteCmd(host, t.command, lang, runAs, sudo)
	case ScriptTask:
		return t.sshClient.ExecuteScript(host, t.scriptFile, t.dstDir, lang, runAs, sudo, t.remove, t.allowOverwrite)
	case PushTask:
		return t.sshClient.PushFiles(host, t.pushFiles.files, t.pushFiles.zipFiles, t.dstDir, t.allowOverwrite)
	case FetchTask:
		return t.sshClient.FetchFiles(host, t.fetchFiles, t.dstDir, t.tmpDir, sudo, runAs)
	default:
		return "", fmt.Errorf("unknown task type: %v", t.taskType)
	}
}

//nolint:gocyclo
// BatchRun ...
func (t *Task) BatchRun() {
	timeNow := time.Now()

	if t.configFlags.Hosts.List {
		allHosts, err := t.ListHosts()
		if err != nil {
			t.err = err
			return
		}

		hostsCount := len(allHosts)

		for _, v := range allHosts {
			fmt.Printf("%s\n", v)
		}

		fmt.Fprintf(os.Stderr, "\nhosts (%d)\n", hostsCount)

		return
	}

	authConf := t.configFlags.Auth
	runConf := t.configFlags.Run

	log.Debugf("Default Auth: login user '%s'", authConf.User)

	if runConf.Sudo {
		log.Debugf("Default Auth: use sudo as user '%s'", runConf.AsUser)
	}

	switch t.taskType {
	case CommandTask:
		if t.command == "" {
			t.err = errors.New("need flag '-e/--execute' or '-L/--hosts.list'")
		}
	case ScriptTask:
		if t.scriptFile == "" {
			t.err = errors.New("need flag '-e/--execute' or '-L/--hosts.list'")
		}
	case PushTask:
		if t.pushFiles == nil || len(t.pushFiles.files) == 0 {
			t.err = errors.New("need flag '-f/--files' or '-L/--hosts.list'")
		}
	case FetchTask:
		if len(t.fetchFiles) == 0 {
			t.err = errors.New("need flag '-f/--files' or '-L/--hosts.list'")
		} else if len(t.dstDir) == 0 {
			t.err = errors.New("need flag '-d/--dest-path' or '-L/--hosts.list'")
		} else {
			if !util.DirExists(t.dstDir) {
				err := os.MkdirAll(t.dstDir, os.ModePerm)
				util.CheckErr(err)
			}
		}
	}

	if t.err != nil {
		return
	}

	t.buildSSHClient()

	allHosts, err := t.getAllHosts()
	if err != nil {
		t.err = err
		return
	}

	log.Debugf("got target hosts, count: %d", len(allHosts))

	result := t.sshClient.BatchRun(allHosts, t)
	successCount, failedCount := 0, 0
	for v := range result {
		if v.Status == batchssh.SuccessIdentifier {
			successCount++
		} else {
			failedCount++
		}

		t.detailOutput <- detailResult{
			taskID:   t.id,
			hostname: v.Host,
			status:   v.Status,
			output:   v.Message,
		}
	}

	elapsed := time.Since(timeNow).Seconds()

	t.taskOutput <- taskResult{
		t.id,
		successCount,
		failedCount,
		elapsed,
	}
}

// HandleOutput ...
func (t *Task) HandleOutput() {
	for res := range t.detailOutput {
		output := ""

		// Fix the problem of special characters ^M appearing at the end of
		// the line break when writing files in text format.
		outputNoR := strings.ReplaceAll(res.output, "\r\n", "\n")

		// Trim leading and trailing blank characters.
		outputNoSpace := strings.TrimSpace(outputNoR)

		// Trim sudo password prompt messages.
		re, err := regexp.Compile(sudoPromptRegex)
		if err != nil {
			log.Debugf("re compile '%s' failed: %s", sudoPromptRegex, err)
		} else {
			output = re.ReplaceAllString(outputNoSpace, "")
		}

		contextLogger := log.WithFields(log.Fields{
			"hostname": res.hostname,
			"status":   res.status,
			"output":   output,
		})

		if res.status == batchssh.SuccessIdentifier {
			contextLogger.Infof("success")
		} else {
			contextLogger.Errorf("failed")
		}
	}

	for res := range t.taskOutput {
		log.Infof(
			"success count: %d, failed count: %d, elapsed: %.2fs",
			res.hostsSuccessCount,
			res.hostsFailureCount,
			res.elapsed,
		)
	}
}

// CheckErr ...
func (t *Task) CheckErr() error {
	return t.err
}

// ListHosts ...
func (t *Task) ListHosts() ([]string, error) {
	var hosts []string

	if len(t.hosts) != 0 {
		for _, hostOrPattern := range t.hosts {
			hostOrPattern = strings.TrimSpace(hostOrPattern)

			if hostOrPattern == "" {
				continue
			}

			hostList, err := expandhost.PatternToHosts(hostOrPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid host pattern: %s", err)
			}

			hosts = append(hosts, hostList...)
		}
	}

	if t.configFlags.Hosts.File != "" {
		content, err := ioutil.ReadFile(t.configFlags.Hosts.File)
		if err != nil {
			return nil, fmt.Errorf("read hosts file failed: %s", err)
		}

		hostSlice := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		for _, hostLine := range hostSlice {
			if hostLine == "" || strings.HasPrefix(hostLine, "#") {
				continue
			}

			hostFields := strings.Fields(hostLine)

			hostAlias := hostFields[0]

			hostList, err := expandhost.PatternToHosts(hostAlias)
			if err != nil {
				return nil, fmt.Errorf("invalid host pattern: %s", err)
			}

			hosts = append(hosts, hostList...)
		}
	}

	return hosts, nil
}

//nolint:funlen,gocyclo
func (t *Task) getAllHosts() ([]*batchssh.Host, error) {
	var hosts []*batchssh.Host

	port := t.configFlags.Hosts.Port

	sshAuthMethods := t.getDefaultSSHAuthMethods()

	if len(t.hosts) != 0 {
		for _, hostOrPattern := range t.hosts {
			hostOrPattern = strings.TrimSpace(hostOrPattern)

			if hostOrPattern == "" {
				continue
			}

			hostList, err := expandhost.PatternToHosts(hostOrPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid host pattern: %s", err)
			}

			for _, v := range hostList {
				hosts = append(hosts, &batchssh.Host{
					Alias:    v,
					Host:     v,
					Port:     port,
					User:     t.defaultUser,
					Password: *t.defaultPass,
					Keys:     t.defaultIdentityFiles,
					SSHAuths: sshAuthMethods,
				})
			}
		}
	}

	if t.configFlags.Hosts.File != "" {
		content, err := ioutil.ReadFile(t.configFlags.Hosts.File)
		if err != nil {
			return nil, fmt.Errorf("read hosts file failed: %s", err)
		}

		var hostVars []string
		for _, v := range hostVarsMap {
			hostVars = append(hostVars, v)
		}

		hostSlice := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		for _, hostLine := range hostSlice {
			if hostLine == "" || strings.HasPrefix(hostLine, "#") {
				continue
			}

			hostUser := t.defaultUser
			hostPassword := *t.defaultPass
			hostPort := port
			hostSSHAuths := sshAuthMethods

			var (
				hostKeys       []string
				hostPassphrase string
			)

			hostFields := strings.Fields(hostLine)

			hostAlias := hostFields[0]

			hostAddr := ""
			if len(hostFields) > 1 {
				for _, v := range hostFields[1:] {
					item := strings.Split(v, "=")
					hostVar := item[0]

					switch hostVar {
					case hostVarsMap[hostVarHost]:
						hostAddr = item[1]
					case hostVarsMap[hostVarPort]:
						hostPort, _ = strconv.Atoi(item[1])
						log.Debugf("Individual Auth: individual port '%d' for '%s'", hostPort, hostAlias)
					case hostVarsMap[hostVarUser]:
						hostUser = item[1]
						log.Debugf("Individual Auth: individual user '%s' for '%s'", hostUser, hostAlias)
					case hostVarsMap[hostVarPassword]:
						hostPassword = item[1]
						assignRealPass(&hostPassword, hostAlias, "password")
						hostSSHAuths = append(hostSSHAuths, ssh.Password(hostPassword))
						log.Debugf("Individual Auth: add individual password auth for '%s'", hostAlias)
					case hostVarsMap[hostVarKeys]:
						hostKeys = strings.Split(item[1], ",")
						hostKeys = parseItentityFiles(hostKeys)
					case hostVarsMap[hostVarPassphrase]:
						hostPassphrase = item[1]
						assignRealPass(&hostPassphrase, hostAlias, "passphrase")
					default:
						log.Warnf(
							"indvalid host var '%s' in host entry '%s', available vars: %s",
							hostVar,
							hostLine,
							hostVars,
						)
					}
				}
			}

			if len(hostKeys) != 0 {
				sshSigners := getSigners(hostKeys, hostPassphrase, "Individual")
				if len(sshSigners) == 0 {
					log.Debugf("Individual Auth: no valid individual identity files for '%s'", hostAlias)
				} else {
					hostSSHAuths = append(hostSSHAuths, ssh.PublicKeys(sshSigners...))
					log.Debugf("Individual Auth: add individual pubkey auth for '%s'", hostAlias)
				}
			}

			hostList, err := expandhost.PatternToHosts(hostAlias)
			if err != nil {
				return nil, fmt.Errorf("invalid host pattern: %s", err)
			}

			for _, v := range hostList {
				if hostAddr == "" {
					hosts = append(hosts, &batchssh.Host{
						Alias:    v,
						Host:     v,
						Port:     hostPort,
						User:     hostUser,
						Password: hostPassword,
						Keys:     hostKeys,
						SSHAuths: hostSSHAuths,
					})
				} else {
					hosts = append(hosts, &batchssh.Host{
						Alias:    v,
						Host:     hostAddr,
						Port:     hostPort,
						User:     hostUser,
						Password: hostPassword,
						Keys:     hostKeys,
						SSHAuths: hostSSHAuths,
					})
				}
			}
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("need target hosts, you can specify hosts file by flag '-H' or " +
			"provide host/pattern as positional arguments")
	}

	return hosts, nil
}

func (t *Task) buildSSHClient() {
	var sshClient *batchssh.Client

	if t.configFlags.Proxy.Server != "" {
		proxyAuths := t.getProxySSHAuthMethods()

		sshClient = batchssh.NewClient(
			batchssh.WithConnTimeout(time.Duration(t.configFlags.Timeout.Conn)*time.Second),
			batchssh.WithCommandTimeout(time.Duration(t.configFlags.Timeout.Command)*time.Second),
			batchssh.WithConcurrency(t.configFlags.Run.Concurrency),
			batchssh.WithProxyServer(
				t.configFlags.Proxy.Server,
				t.configFlags.Proxy.User,
				t.configFlags.Proxy.Port,
				proxyAuths,
			),
		)
	} else {
		sshClient = batchssh.NewClient(
			batchssh.WithConnTimeout(time.Duration(t.configFlags.Timeout.Conn)*time.Second),
			batchssh.WithCommandTimeout(time.Duration(t.configFlags.Timeout.Command)*time.Second),
			batchssh.WithConcurrency(t.configFlags.Run.Concurrency),
		)
	}

	t.sshClient = sshClient
}

func (t *Task) getDefaultSSHAuthMethods() []ssh.AuthMethod {
	var (
		auths    []ssh.AuthMethod
		sshAgent net.Conn
		err      error
	)

	if *t.defaultPass != "" {
		auths = append(auths, ssh.Password(*t.defaultPass))
	} else {
		log.Debugf("Default Auth: password of the login user '%s' not provided", t.defaultUser)
	}

	if len(t.defaultIdentityFiles) != 0 {
		sshSigners := getSigners(t.defaultIdentityFiles, t.configFlags.Auth.Passphrase, "Default")
		if len(sshSigners) == 0 {
			log.Debugf("Default Auth: no valid default identity files")
		} else {
			auths = append(auths, ssh.PublicKeys(sshSigners...))
		}
	}

	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		sshAgent, err = net.Dial("unix", sshAuthSock)
		if err != nil {
			log.Debugf("Default Auth: connect ssh-agent failed: %s", err)
		} else {
			log.Debugf("Default Auth: connected to SSH_AUTH_SOCK: %s", sshAuthSock)

			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		}

		t.sshAgent = sshAgent
	}

	if *t.defaultPass == "" && t.configFlags.Run.Sudo {
		log.Debugf(
			"Default Auth: using sudo as other user needs password. Prompt for password of the login user '%s'",
			t.defaultUser,
		)

		*t.defaultPass = getPasswordFromPrompt(t.defaultUser)
		auths = append(auths, ssh.Password(*t.defaultPass))
	}

	return auths
}

func (t *Task) getProxySSHAuthMethods() []ssh.AuthMethod {
	var (
		proxyAuths []ssh.AuthMethod
		sshAgent   net.Conn
	)

	log.Debugf("Proxy Auth: proxy login user: %s", t.configFlags.Proxy.User)

	if t.configFlags.Proxy.Password != "" {
		proxyAuths = append(proxyAuths, ssh.Password(t.configFlags.Proxy.Password))
	} else {
		proxyAuths = append(proxyAuths, ssh.Password(*t.defaultPass))
	}
	log.Debugf("Proxy Auth: received password of the proxy user")

	proxyKeyfiles := parseItentityFiles(t.configFlags.Proxy.IdentityFiles)
	if len(proxyKeyfiles) != 0 {
		sshSigners := getSigners(proxyKeyfiles, t.configFlags.Proxy.Passphrase, "Proxy")
		if len(sshSigners) == 0 {
			log.Debugf("Proxy Auth: no valid identity files for proxy")
		} else {
			proxyAuths = append(proxyAuths, ssh.PublicKeys(sshSigners...))
		}
	}

	if t.sshAgent != nil {
		log.Debugf("Proxy Auth: connected to default SSH_AUTH_SOCK")

		agentSigners := ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
		proxyAuths = append(proxyAuths, agentSigners)
	}

	return proxyAuths
}

func getDefaultPassword(auth *configflags.Auth) string {
	var password string

	authFile := auth.PassFile
	if authFile != "" {
		var passwordContent []byte

		passwordContent, err := ioutil.ReadFile(authFile)
		if err != nil {
			err = fmt.Errorf("read password file '%s' failed: %w", authFile, err)
		}
		util.CheckErr(err)

		password = strings.TrimSpace(string(passwordContent))

		log.Debugf("Default Auth: read password of user '%s' from file '%s'", authFile, auth.User)
	}

	passwordFromFlag := auth.Password
	if passwordFromFlag != "" {
		password = passwordFromFlag

		log.Debugf("Default Auth: received password of user '%s' from commandline flag or configuration file", auth.User)
	}

	assignRealPass(&password, "default", "password")

	if auth.AskPass {
		log.Debugf("Default Auth: ask for password of user '%s' by flag '-k/--auth.ask-pass'", auth.User)
		password = getPasswordFromPrompt(auth.User)
	}

	return password
}

func parseItentityFiles(identityFiles []string) (keyFiles []string) {
	homeDir := os.Getenv("HOME")
	for _, file := range identityFiles {
		if strings.HasPrefix(file, "~/") {
			file = strings.Replace(file, "~", homeDir, 1)
		}

		keyFiles = append(keyFiles, file)
	}

	return
}

func getSigners(keyfiles []string, passphrase string, authKind string) []ssh.Signer {
	var (
		signers []ssh.Signer
		msgHead string
	)

	msgHead = authKind + " Auth: "

	for _, f := range keyfiles {
		signer, msg := getSigner(f, passphrase)

		log.Debugf("%s%s", msgHead, msg)

		if signer != nil {
			signers = append(signers, signer)
		}
	}

	return signers
}

func getSigner(keyfile, passphrase string) (ssh.Signer, string) {
	buf, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Sprintf("read identity file '%s' failed: %s", keyfile, err)
	}

	pubkey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		_, ok := err.(*ssh.PassphraseMissingError)
		if ok {
			pubkeyWithPassphrase, err1 := sshkeys.ParseEncryptedPrivateKey(buf, []byte(passphrase))
			if err1 != nil {
				return nil, fmt.Sprintf("parse identity file '%s' with passphrase failed: %s", keyfile, err1)
			}

			return pubkeyWithPassphrase, fmt.Sprintf("parsed identity file '%s' with passphrase", keyfile)
		}

		return nil, fmt.Sprintf("parse identity file '%s' failed: %s", keyfile, err)
	}

	return pubkey, fmt.Sprintf("parsed identity file '%s'", keyfile)
}

func getPasswordFromPrompt(loginUser string) string {
	fmt.Fprintf(os.Stderr, "Password for %s: ", loginUser)

	var passwordByte []byte
	passwordByte, err := term.ReadPassword(0)
	if err != nil {
		err = fmt.Errorf("get password from terminal failed: %s", err)
	}
	util.CheckErr(err)

	password := string(passwordByte)

	fmt.Println("")

	log.Debugf("Default Auth: received password of the login user '%s' from terminal prompt", loginUser)

	return password
}

func assignRealPass(pass *string, host, objectType string) {
	var err error

	if aes.IsAES256CipherText(*pass) {
		vaultPass := vault.GetVaultPassword()

		*pass, err = aes.AES256Decode(*pass, vaultPass)
		if err != nil {
			log.Debugf("Vault: decrypt %s for '%s' failed: %s", objectType, host, err)
			util.CheckErr(err)
		}

		log.Debugf("Vault: decrypt %s for '%s' success", objectType, host)
	}
}
