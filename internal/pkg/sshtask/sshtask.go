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
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/batchssh"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

// TaskType ...
type TaskType int

// ...
const (
	CommandTask TaskType = iota
	ScriptTask
	PushTask
)

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

// Task ...
type Task struct {
	configFlags *configflags.ConfigFlags

	id        string
	taskType  TaskType
	sshClient *batchssh.Client

	// hostnames or ips from command line arguments.
	hosts []string

	command    string
	scriptFile string
	copyFiles  []string
	dstDir     string
	remove     bool

	taskOutput   chan taskResult
	detailOutput chan detailResult
}

// NewTask ...
func NewTask(taskType TaskType, configFlags *configflags.ConfigFlags) *Task {
	return &Task{
		configFlags:  configFlags,
		id:           time.Now().Format("20060102150405"),
		taskType:     taskType,
		taskOutput:   make(chan taskResult, 1),
		detailOutput: make(chan detailResult),
	}
}

// Start task.
func (t *Task) Start() {
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

// SetHosts ...
func (t *Task) SetHosts(hosts []string) {
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

// SetCopyfiles ...
func (t *Task) SetCopyfiles(files []string) {
	t.copyFiles = files
}

// SetScriptOptions ...
func (t *Task) SetScriptOptions(destPath string, remove bool) {
	t.dstDir = destPath
	t.remove = remove
}

// SetFileOptions ...
func (t *Task) SetFileOptions(destPath string) {
	t.dstDir = destPath
}

// RunSSH implements batchssh.Task
func (t *Task) RunSSH(addr string) (string, error) {
	lang := t.configFlags.Run.Lang
	runAs := t.configFlags.Run.AsUser
	sudo := t.configFlags.Run.Sudo

	switch t.taskType {
	case CommandTask:
		return t.sshClient.ExecuteCmd(addr, t.command, lang, runAs, sudo)
	case ScriptTask:
		return t.sshClient.ExecuteScript(addr, t.scriptFile, t.dstDir, lang, runAs, sudo, t.remove)
	case PushTask:
		return t.sshClient.CopyFiles(addr, t.copyFiles, t.dstDir)
	default:
		return "", fmt.Errorf("unknown task type: %v", t.taskType)
	}
}

// BatchRun ...
func (t *Task) BatchRun() {
	timeNow := time.Now()

	allHosts, err := t.getAllHosts()
	if err != nil {
		util.CheckErr(err)
	}

	t.buildSSHClient()

	result := t.sshClient.BatchRun(allHosts, t)
	successCount, failedCount := 0, 0
	for v := range result {
		if v.Status == "Success" {
			successCount++
		} else {
			failedCount++
		}

		t.detailOutput <- detailResult{
			taskID:   t.id,
			hostname: v.Addr,
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
		// delete ^M
		outputNoR := strings.ReplaceAll(res.output, "\r\n", "\n")
		outputNoSpace := strings.TrimSpace(outputNoR)
		re, _ := regexp.Compile(`^\[sudo\] password for [a-zA-Z0-9]+: \n|^\[sudo\] [a-zA-Z0-9]+ 的密码：\n`)

		output := re.ReplaceAllString(outputNoSpace, "")

		contextLogger := log.WithFields(log.Fields{
			"hostname": res.hostname,
			"status":   res.status,
			"output":   output,
		})

		if res.status == "Success" {
			contextLogger.Infof("success")
		} else {
			contextLogger.Errorf("failed")
		}
	}

	for res := range t.taskOutput {
		log.Infof(
			"success count: %d, failed count: %d, elapsed: %2.fs",
			res.hostsSuccessCount,
			res.hostsFailureCount,
			res.elapsed,
		)
	}
}

func (t *Task) getAllHosts() ([]string, error) {
	var hosts []string

	if len(t.hosts) != 0 {
		hosts = t.hosts
	}

	if t.configFlags.Hosts.File != "" {
		content, err := ioutil.ReadFile(t.configFlags.Hosts.File)
		if err != nil {
			return nil, fmt.Errorf("read hosts file failed: %s", err)
		}

		hostSlice := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		hosts = append(hosts, hostSlice...)
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts provided")
	}

	return hosts, nil
}

func (t *Task) buildSSHClient() {
	user, password, sshAuthSock, keys, err := t.getAuthInfo()
	if err != nil {
		util.CheckErr(err)
	}

	sshClient, err := batchssh.NewClient(
		user,
		password,
		sshAuthSock,
		keys,
		batchssh.WithConnTimeout(time.Duration(t.configFlags.Timeout.Conn)*time.Second),
		batchssh.WithCommandTimeout(time.Duration(t.configFlags.Timeout.Command)*time.Second),
		batchssh.WithConcurrency(t.configFlags.Run.Concurrency),
		batchssh.WithPort(t.configFlags.Hosts.Port),
	)

	if err != nil {
		util.CheckErr(err)
	}

	t.sshClient = sshClient
}

func (t *Task) getAuthInfo() (user, password, sshAuthSock string, keys []string, err error) {
	user = t.configFlags.Auth.User

	sshAuthSock = os.Getenv("SSH_AUTH_SOCK")

	if t.configFlags.Auth.Pubkey {
		homeDir := os.Getenv("HOME")
		for _, file := range t.configFlags.Auth.IdentityFiles {
			if strings.HasPrefix(file, "~/") {
				file = strings.Replace(file, "~", homeDir, 1)
			}

			keys = append(keys, file)
		}
	}

	authFile := t.configFlags.Auth.File
	if authFile != "" {
		var authContent []byte
		authContent, err = ioutil.ReadFile(authFile)
		if err != nil {
			err = fmt.Errorf("read auth file failed: %w", err)
			return
		}

		contentTrim := strings.TrimSpace(string(authContent))
		auths := strings.Split(contentTrim, ":")

		if len(auths) != 2 {
			err = errors.New("invalid auth file format")
			return
		}

		user = auths[0]
		password = auths[1]
	}

	passwordFlag := t.configFlags.Auth.Password

	if passwordFlag != "" {
		password = passwordFlag
	}

	if (password == "" && !t.configFlags.Auth.Pubkey) || (t.configFlags.Run.Sudo && password == "") {
		fmt.Fprintf(os.Stderr, "Password: ")

		var passwordByte []byte
		passwordByte, err = term.ReadPassword(0)
		if err != nil {
			err = fmt.Errorf("get password from terminal failed: %w", err)
			return
		}

		password = string(passwordByte)
		fmt.Println("")
	}

	//nolint:nakedret
	return
}
