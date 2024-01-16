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
	"net"
	"os"
	"regexp"
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
	"github.com/windvalley/gossh/pkg/inventory"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

var (
	linuxUserRegex  = "[a-zA-Z0-9_.-]+[$]?"
	sudoPromptRegex = fmt.Sprintf(
		`(?s).*\[sudo\] password for %s:(\n|)|(?s).*\[sudo\] %s 的密码：(\n|)`,
		linuxUserRegex,
		linuxUserRegex,
	)
)

type TaskType int

const (
	CommandTask TaskType = iota
	ScriptTask
	PushTask
	FetchTask
)

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

// Task is a ssh task for one or more hosts.
type Task struct {
	configFlags *configflags.ConfigFlags

	id       string
	taskType TaskType

	sshClient             *batchssh.Client
	sshAgent              net.Conn
	defaultUser           string
	defaultPass           string
	defaultIdentityFiles  []string
	defaultSSHAuthMethods []ssh.AuthMethod

	// Hostname or IP or host pattern or host group from command line arguments.
	argHosts []string

	command    string
	scriptFile string

	pushFiles      *pushFiles
	fetchFiles     []string
	dstDir         string
	tmpDir         string
	remove         bool
	allowOverwrite bool
	enableZip      bool

	taskOutput   chan taskResult
	detailOutput chan detailResult

	err error
}

// NewTask create a new task.
func NewTask(taskType TaskType, configFlags *configflags.ConfigFlags) *Task {
	defaultIdentityFiles := parseItentityFiles(configFlags.Auth.IdentityFiles)

	defaultPass := getDefaultPassword(configFlags.Auth)

	return &Task{
		configFlags:          configFlags,
		id:                   time.Now().Format("20060102150405"),
		taskType:             taskType,
		defaultUser:          configFlags.Auth.User,
		defaultPass:          defaultPass,
		defaultIdentityFiles: defaultIdentityFiles,
		taskOutput:           make(chan taskResult, 1),
		detailOutput:         make(chan detailResult),
	}
}

// SSH implements batchssh.Tasker.
func (t *Task) SSH(host *batchssh.Host) (string, error) {
	lang := t.configFlags.Run.Lang
	runAs := t.configFlags.Run.AsUser
	sudo := t.configFlags.Run.Sudo

	switch t.taskType {
	case CommandTask:
		return t.sshClient.ExecuteCmd(host, t.command, lang, runAs, sudo)
	case ScriptTask:
		return t.sshClient.ExecuteScript(host, t.scriptFile, t.dstDir, lang, runAs, sudo, t.remove, t.allowOverwrite)
	case PushTask:
		return t.sshClient.PushFiles(host, t.pushFiles.files, t.pushFiles.zipFiles, t.dstDir, t.allowOverwrite, t.enableZip)
	case FetchTask:
		hosts, err := t.getAllHosts()
		if err != nil {
			return "", err
		}
		return t.sshClient.FetchFiles(host, t.fetchFiles, t.dstDir, t.tmpDir, sudo, runAs, t.enableZip, len(hosts))
	default:
		return "", fmt.Errorf("unknown task type: %v", t.taskType)
	}
}

// Start to run ssh task.
func (t *Task) Start() {
	if t.sshAgent != nil {
		defer t.sshAgent.Close()
	}

	go func() {
		defer close(t.taskOutput)
		defer close(t.detailOutput)
		t.batchRunSSH()
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

	t.handleOutput()
}

//nolint:gocyclo
func (t *Task) batchRunSSH() {
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

	switch t.taskType {
	case CommandTask:
		if t.command == "" {
			t.err = errors.New("need flag '-e/--execute' or '-l/--hosts.list'")
		}
	case ScriptTask:
		if t.scriptFile == "" {
			t.err = errors.New("need flag '-e/--execute' or '-l/--hosts.list'")
		}
	case PushTask:
		if t.pushFiles == nil || len(t.pushFiles.files) == 0 {
			t.err = errors.New("need flag '-f/--files' or '-l/--hosts.list'")
		}
	case FetchTask:
		if len(t.fetchFiles) == 0 {
			t.err = errors.New("need flag '-f/--files' or '-l/--hosts.list'")
		} else if len(t.dstDir) == 0 {
			t.err = errors.New("need flag '-d/--dest-path' or '-l/--hosts.list'")
		} else {
			if !util.DirExists(t.dstDir) {
				if err := os.MkdirAll(t.dstDir, os.ModeDir); err != nil {
					util.PrintErrExit(err)
				}
			}
		}
	}

	if t.err != nil {
		return
	}

	authConf := t.configFlags.Auth
	runConf := t.configFlags.Run

	log.Debugf("Auth: login user '%s'", authConf.User)

	if runConf.Sudo {
		log.Debugf("Auth: use sudo as user '%s'", runConf.AsUser)
	}

	t.setDefaultSSHAuthMethods()

	t.buildSSHClient()

	allHosts, err := t.getAllHosts()
	if err != nil {
		t.err = err
		return
	}

	log.Debugf("Got target hosts, count: %d", len(allHosts))

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

func (t *Task) handleOutput() {
	for res := range t.detailOutput {
		// Fix the problem of special characters ^M appearing at the end of
		// the line break when writing files in text format.
		outputNoR := strings.ReplaceAll(res.output, "\r\n", "\n")

		// Trim sudo password prompt messages.
		outputNoSudoPrompt := ""
		re, err := regexp.Compile(sudoPromptRegex)
		if err != nil {
			log.Debugf("regexp compile '%s' failed: %s", sudoPromptRegex, err)
		} else {
			outputNoSudoPrompt = re.ReplaceAllString(outputNoR, "")
		}

		// Trim leading and trailing blank characters.
		output := strings.TrimSpace(outputNoSudoPrompt)

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

func (t *Task) SetTargetHosts(hosts []string) {
	t.argHosts = hosts
}

func (t *Task) SetCommand(command string) {
	t.command = command
}

func (t *Task) SetScriptFile(sciptFile string) {
	t.scriptFile = sciptFile
}

func (t *Task) SetPushfiles(files, zipFiles []string) {
	t.pushFiles = &pushFiles{
		files:    files,
		zipFiles: zipFiles,
	}
}

func (t *Task) SetFetchFiles(files []string) {
	t.fetchFiles = files
}

func (t *Task) SetScriptOptions(destPath string, remove, allowOverwrite bool) {
	t.dstDir = destPath
	t.remove = remove
	t.allowOverwrite = allowOverwrite
}

func (t *Task) SetPushOptions(destPath string, allowOverwrite, enableZip bool) {
	t.dstDir = destPath
	t.allowOverwrite = allowOverwrite
	t.enableZip = enableZip
}

func (t *Task) SetFetchOptions(destPath, tmpDir string, enableZipFiles bool) {
	t.dstDir = destPath
	t.tmpDir = tmpDir
	t.enableZip = enableZipFiles
}

func (t *Task) CheckErr() error {
	return t.err
}

func (t *Task) ListHosts() ([]string, error) {
	var hosts []string

	if t.configFlags.Hosts.Inventory == "" {
		if len(t.argHosts) != 0 {
			for _, hostOrPattern := range t.argHosts {
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

		return deDuplicate(hosts), nil
	}

	targetHosts, err := t.getInventoryHosts()
	if err != nil {
		return nil, err
	}

	for _, v := range inventory.DeDuplHosts(targetHosts) {
		hosts = append(hosts, v.Alias)
	}

	return hosts, nil
}

func (t *Task) getAllHosts() ([]*batchssh.Host, error) {
	var hosts []*batchssh.Host

	helpErr := errors.New(
		"need target hosts, you can specify hosts file by flag '-i', provide host/pattern/group as positional arguments")

	if t.configFlags.Hosts.Inventory == "" {
		if len(t.argHosts) != 0 {
			for _, hostOrPattern := range t.argHosts {
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
						Port:     t.configFlags.Hosts.Port,
						User:     t.defaultUser,
						Password: t.defaultPass,
						Keys:     t.defaultIdentityFiles,
						SSHAuths: t.defaultSSHAuthMethods,
					})
				}
			}

			return deDuplSSHHosts(hosts), nil
		}

		return nil, helpErr
	}

	targetHosts, err := t.getInventoryHosts()
	if err != nil {
		return nil, err
	}

	if len(targetHosts) == 0 {
		return nil, helpErr
	}

	for _, v := range inventory.DeDuplHosts(targetHosts) {
		var hostSSHAuths []ssh.AuthMethod

		if v.Port == 0 {
			v.Port = t.configFlags.Hosts.Port
		} else {
			log.Debugf("Host Info: individual port '%d' for '%s'", v.Port, v.Alias)
		}

		if v.User == "" {
			v.User = t.defaultUser
		} else {
			log.Debugf("Host Info: individual user '%s' for '%s'", v.User, v.Alias)
		}

		if len(v.Keys) != 0 {
			keys := parseItentityFiles(v.Keys)
			passphrase := getRealPass(v.Passphrase, v.Alias, "passphrase")
			sshSigners := getSigners(keys, passphrase, "Individual")
			if len(sshSigners) == 0 {
				log.Debugf("Individual Auth: no valid individual identity files for '%s'", v.Alias)
			} else {
				hostSSHAuths = append(hostSSHAuths, ssh.PublicKeys(sshSigners...))
				log.Debugf("Individual Auth: add individual pubkey auth for '%s'", v.Alias)
			}
		}

		realPassword := ""
		if v.Password == "" {
			realPassword = getRealPass(t.defaultPass, v.Alias, "password")
		} else {
			realPassword = getRealPass(v.Password, v.Alias, "password")
			hostSSHAuths = append(hostSSHAuths, ssh.Password(v.Password))
			log.Debugf("Individual Auth: add individual password for '%s'", v.Alias)
		}

		hostSSHAuths = append(hostSSHAuths, t.defaultSSHAuthMethods...)

		hosts = append(hosts, &batchssh.Host{
			Alias:    v.Alias,
			Host:     v.Host,
			Port:     v.Port,
			User:     v.User,
			Password: realPassword,
			Keys:     v.Keys,
			SSHAuths: hostSSHAuths,
		})
	}

	return hosts, nil
}

func (t *Task) getInventoryHosts() ([]*inventory.Host, error) {
	var fileHosts []*inventory.Host

	if err := inventory.Parse(t.configFlags.Hosts.Inventory); err != nil {
		return nil, err
	}

	if len(t.argHosts) == 0 {
		fileHosts = inventory.GetAllHosts()
	} else {
		for _, v := range t.argHosts {
			hostList, err := expandhost.PatternToHosts(v)
			if err != nil {
				return nil, fmt.Errorf("invalid host pattern: %s", err)
			}

			for _, host := range hostList {
				_fileHosts := inventory.GetHostsByGroup(host)
				if _fileHosts == nil {
					_host := inventory.GetHostByAlias(host)
					if _host != nil {
						_fileHosts = []*inventory.Host{_host}
					} else {
						_fileHosts = []*inventory.Host{
							{
								Alias: host,
								Host:  host,
							},
						}
					}
				}

				fileHosts = append(fileHosts, _fileHosts...)
			}
		}
	}

	return fileHosts, nil
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

func (t *Task) setDefaultSSHAuthMethods() {
	var (
		signers  []ssh.Signer
		auths    []ssh.AuthMethod
		sshAgent net.Conn
		err      error
	)

	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		sshAgent, err = net.Dial("unix", sshAuthSock)
		if err != nil {
			log.Debugf("Auth: connect ssh-agent failed: %s", err)
		} else {
			log.Debugf("Auth: connected to SSH_AUTH_SOCK: %s", sshAuthSock)

			signers, err = agent.NewClient(sshAgent).Signers()
			if err != nil {
				log.Debugf("Auth: parse ssh-agent failed: %v", err)
			} else {
				log.Debugf("Auth: parse ssh-agent success")
			}
		}

		t.sshAgent = sshAgent
	}

	if len(t.defaultIdentityFiles) != 0 {
		sshSigners := getSigners(t.defaultIdentityFiles, t.configFlags.Auth.Passphrase, "")

		if len(sshSigners) != 0 {
			signers = append(signers, sshSigners...)
		} else {
			log.Debugf("Auth: no valid default identity files")
		}
	}

	if len(signers) != 0 {
		auths = append(auths, ssh.PublicKeys(signers...))
	}

	if t.defaultPass != "" {
		auths = append(auths, ssh.Password(t.defaultPass))
	} else {
		log.Debugf("Auth: password of the login user '%s' not provided", t.defaultUser)
	}

	if t.defaultPass == "" && t.configFlags.Run.Sudo {
		log.Debugf(
			"Auth: using sudo as other user needs password. Prompt for password of the login user '%s'",
			t.defaultUser,
		)

		t.defaultPass = getPasswordFromPrompt(t.defaultUser)
		auths = append(auths, ssh.Password(t.defaultPass))
	}

	t.defaultSSHAuthMethods = auths
}

func (t *Task) getProxySSHAuthMethods() []ssh.AuthMethod {
	var (
		signers    []ssh.Signer
		proxyAuths []ssh.AuthMethod
		err        error
	)

	log.Debugf("Proxy Auth: proxy login user: %s", t.configFlags.Proxy.User)

	if t.sshAgent != nil {
		log.Debugf("Proxy Auth: use default auth SSH_AUTH_SOCK")

		signers, err = agent.NewClient(t.sshAgent).Signers()
		if err != nil {
			log.Debugf("Proxy Auth: parse default ssh-agent failed: %v", err)
		} else {
			log.Debugf("Proxy Auth: parse default ssh-agent success")
		}
	}

	proxyKeyfiles := parseItentityFiles(t.configFlags.Proxy.IdentityFiles)
	if len(proxyKeyfiles) != 0 {
		sshSigners := getSigners(proxyKeyfiles, t.configFlags.Proxy.Passphrase, "Proxy")

		if len(sshSigners) != 0 {
			signers = append(signers, sshSigners...)
		} else {
			log.Debugf("Proxy Auth: no valid identity files for proxy")
		}
	}

	if len(signers) != 0 {
		proxyAuths = append(proxyAuths, ssh.PublicKeys(signers...))
	}

	if t.configFlags.Proxy.Password != "" {
		proxyAuths = append(proxyAuths, ssh.Password(t.configFlags.Proxy.Password))
	} else {
		proxyAuths = append(proxyAuths, ssh.Password(t.defaultPass))
	}
	log.Debugf("Proxy Auth: received password of the proxy user")

	return proxyAuths
}

func getDefaultPassword(auth *configflags.Auth) string {
	var password string

	authFile := auth.PassFile
	if authFile != "" {
		var passwordContent []byte

		passwordContent, err := os.ReadFile(authFile)
		if err != nil {
			err = fmt.Errorf("read password file '%s' failed: %w", authFile, err)
			util.PrintErrExit(err)
		}

		password = strings.TrimSpace(string(passwordContent))

		log.Debugf("Auth: read password of user '%s' from file '%s'", authFile, auth.User)
	}

	passwordFromFlag := auth.Password
	if passwordFromFlag != "" {
		password = passwordFromFlag

		log.Debugf("Auth: received password of user '%s' from commandline flag or configuration file", auth.User)
	}

	realPassword := getRealPass(password, "default", "password")

	if auth.AskPass {
		log.Debugf("Auth: ask for password of user '%s' by flag '-k/--auth.ask-pass'", auth.User)
		realPassword = getPasswordFromPrompt(auth.User)
	}

	return realPassword
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

	msgHead = "Auth: "
	if authKind != "" {
		msgHead = authKind + " Auth: "
	}

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
	buf, err := os.ReadFile(keyfile)
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
		util.PrintErrExit(err)
	}

	password := string(passwordByte)

	fmt.Println("")

	log.Debugf("Auth: received password of the login user '%s' from terminal prompt", loginUser)

	return password
}

func getRealPass(pass string, host, objectType string) string {
	if aes.IsAES256CipherText(pass) {
		vaultPass := vault.GetVaultPassword()

		realPass, err := aes.AES256Decode(pass, vaultPass)
		if err != nil {
			log.Debugf("Vault: decrypt %s for '%s' failed: %s", objectType, host, err)
			util.PrintErrExit(err)
		}

		log.Debugf("Vault: decrypt %s for '%s' success", objectType, host)

		return realPass
	}

	return pass
}

func deDuplicate(hosts []string) []string {
	var set []string

	keys := make(map[string]bool)

	for _, v := range hosts {
		if !keys[v] {
			set = append(set, v)
			keys[v] = true
		}
	}

	return set
}

func deDuplSSHHosts(hosts []*batchssh.Host) []*batchssh.Host {
	var set []*batchssh.Host

	keys := make(map[string]bool)

	for _, v := range hosts {
		if !keys[v.Alias] {
			set = append(set, v)
			keys[v.Alias] = true
		}
	}

	return set
}
