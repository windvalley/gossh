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

package batchssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/windvalley/gossh/pkg/log"
)

const (
	exportLangPattern = "export LANG=%s;export LC_ALL=%s;export LANGUAGE=%s;"

	// SuccessIdentifier for result output.
	SuccessIdentifier = "SUCCESS"
	// FailedIdentifier for result output.
	FailedIdentifier = "FAILED"
)

// Tasker for ssh.
type Tasker interface {
	SSH(host *Host) (string, error)
}

// Result of ssh command.
type Result struct {
	Host    string `json:"host"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Client for ssh.
type Client struct {
	ConnTimeout    time.Duration
	CommandTimeout time.Duration
	Concurrency    int
	Proxy          *Proxy
}

// Proxy server.
type Proxy struct {
	SSHClient *ssh.Client
	Err       error
}

// Host target host.
type Host struct {
	Alias      string
	Host       string
	Port       int
	User       string
	Password   string
	Keys       []string
	Passphrase string
	SSHAuths   []ssh.AuthMethod
}

// NewClient session.
func NewClient(options ...func(*Client)) *Client {
	client := Client{
		ConnTimeout:    10 * time.Second,
		CommandTimeout: 0,
		Concurrency:    100,
		Proxy:          &Proxy{},
	}

	for _, option := range options {
		option(&client)
	}

	return &client
}

// BatchRun command on remote servers.
func (c *Client) BatchRun(hosts []*Host, sshTask Tasker) <-chan *Result {
	hostCh := make(chan *Host)
	go func() {
		defer close(hostCh)
		for _, host := range hosts {
			hostCh <- host
		}
	}()

	resCh := make(chan *Result)
	var wg sync.WaitGroup
	wg.Add(c.Concurrency)
	for i := 0; i < c.Concurrency; i++ {
		go func(wg *sync.WaitGroup) {
			for host := range hostCh {
				var result *Result

				done := make(chan struct{})
				go func() {
					defer close(done)

					output, err := sshTask.SSH(host)
					if err != nil {
						result = &Result{host.Alias, FailedIdentifier, err.Error()}
					} else {
						result = &Result{host.Alias, SuccessIdentifier, output}
					}
				}()

				if c.CommandTimeout > 0 {
					select {
					case <-done:
					case <-time.After(c.CommandTimeout):
						result = &Result{
							host.Host,
							FailedIdentifier,
							fmt.Sprintf(
								"command timeout, timeout value: %d seconds",
								c.CommandTimeout/time.Second,
							),
						}
					}
				} else {
					<-done
				}

				resCh <- result
			}

			wg.Done()
		}(&wg)
	}

	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(resCh)
	}(&wg)

	return resCh
}

// ExecuteCmd on remote host.
func (c *Client) ExecuteCmd(host *Host, command, lang, runAs string, sudo bool) (string, error) {
	client, err := c.getClient(host)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	exportLang := ""
	if lang != "" {
		exportLang = fmt.Sprintf(exportLangPattern, lang, lang, lang)
	}

	if sudo {
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s'", exportLang, runAs, command)
	} else {
		command = exportLang + command
	}

	return c.executeCmd(session, command, host)
}

// ExecuteScript on remote host.
func (c *Client) ExecuteScript(
	host *Host,
	srcFile, dstDir, lang, runAs string,
	sudo, remove, allowOverwrite bool,
) (string, error) {
	client, err := c.getClient(host)
	if err != nil {
		return "", err
	}
	defer client.Close()

	ftpC, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer ftpC.Close()

	file, err := c.pushFile(ftpC, srcFile, dstDir, host.Host, allowOverwrite)
	if err != nil {
		return "", err
	}

	//nolint:gomnd,govet
	if err := file.Chmod(0755); err != nil {
		return "", err
	}

	script := file.Name()
	file.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	exportLang := ""
	if lang != "" {
		exportLang = fmt.Sprintf(exportLangPattern, lang, lang, lang)
	}

	command := ""
	switch {
	case sudo && remove:
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s;rc=$?;rm -f %s;exit $rc'", exportLang, runAs, script, script)
	case sudo && !remove:
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s'", exportLang, runAs, script)
	case !sudo && remove:
		command = fmt.Sprintf("%s%s;rc=$?;rm -f %s;exit $rc", exportLang, script, script)
	case !sudo && !remove:
		command = exportLang + script
	}

	return c.executeCmd(session, command, host)
}

// PushFiles to remote host.
func (c *Client) PushFiles(
	host *Host,
	srcFiles, srcZipFiles []string,
	dstDir string,
	allowOverwrite, enableZip bool,
) (string, error) {
	client, err := c.getClient(host)
	if err != nil {
		return "", err
	}
	defer client.Close()

	ftpC, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer ftpC.Close()

	if !enableZip {
		for _, srcFile := range srcFiles {
			err = c.pushFileOrDirV2(client, ftpC, srcFile, dstDir, host.Host, allowOverwrite)
			if err != nil {
				return "", err
			}
		}
	} else {
		for i, f := range srcZipFiles {
			srcFile := srcFiles[i]

			dstZipFile := filepath.Base(f)

			done := make(chan struct{})
			var (
				err  error
				file *sftp.File
			)
			go func() {
				defer close(done)

				file, err = pushZipFile(ftpC, f, filepath.Base(srcFile), dstDir, host.Host, allowOverwrite)
				if err == nil {
					file.Close()
				}
			}()

			<-done

			if err != nil {
				return "", err
			}

			session, err := client.NewSession()
			if err != nil {
				return "", err
			}
			defer session.Close()

			_, err = c.executeCmd(
				session,
				fmt.Sprintf(
					`which unzip &>/dev/null && { cd %s;unzip -o %s;rm %s;} || 
				{ echo "need install 'unzip' command";cd %s;rm %s;exit 1;}`,
					dstDir,
					dstZipFile,
					dstZipFile,
					dstDir,
					dstZipFile,
				),
				host,
			)
			if err != nil {
				return "", err
			}

			log.Debugf("%s: %s unzipped", host.Host, f)
		}
	}

	hasOrHave := "has"
	if len(srcFiles) > 1 {
		hasOrHave = "have"
	}

	return fmt.Sprintf("'%s' %s been copied to '%s'", strings.Join(srcFiles, ","), hasOrHave, dstDir), nil
}

// FetchFiles from remote host.
//
//nolint:funlen,gocyclo
func (c *Client) FetchFiles(
	host *Host,
	srcFiles []string,
	dstDir, tmpDir string,
	sudo bool,
	runAs string,
	enableZip bool,
	hostCount int,
) (string, error) {
	client, err := c.getClient(host)
	if err != nil {
		return "", err
	}
	defer client.Close()

	ftpC, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer ftpC.Close()

	var (
		validSrcFiles    []string
		notExistSrcFiles []string
		noPermSrcFiles   []string
	)
	for _, f := range srcFiles {
		if _, err1 := ftpC.Stat(f); err1 != nil {
			if errors.Is(err1, os.ErrNotExist) {
				notExistSrcFiles = append(notExistSrcFiles, f)
				continue
			}

			if !sudo || !enableZip {
				if err, ok := err1.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
					noPermSrcFiles = append(noPermSrcFiles, f)
					continue
				}
			}
		}

		validSrcFiles = append(validSrcFiles, f)
	}

	if len(validSrcFiles) == 0 {
		var err2 error
		if len(notExistSrcFiles) != 0 && len(noPermSrcFiles) != 0 {
			err2 = fmt.Errorf("'%s' not exist; '%s' no permission",
				strings.Join(notExistSrcFiles, ","),
				strings.Join(noPermSrcFiles, ","),
			)
		} else if len(notExistSrcFiles) != 0 {
			err2 = fmt.Errorf("'%s' not exist", strings.Join(notExistSrcFiles, ","))
		} else if len(noPermSrcFiles) != 0 {
			err2 = fmt.Errorf("'%s' no permission", strings.Join(noPermSrcFiles, ","))
		}

		return "", err2
	}

	if hostCount > 1 {
		dstDir = filepath.Join(dstDir, host.Host)
		err = os.MkdirAll(dstDir, os.ModePerm)
		if err != nil {
			return "", fmt.Errorf("make local dir '%s' failed: %v", dstDir, err)
		}
		log.Debugf("make local dir '%s'", dstDir)
	}

	if enableZip {
		for _, f := range validSrcFiles {
			err = c.fetchFileWithZip(client, ftpC, f, dstDir, tmpDir, runAs, host)
			if err != nil {
				return "", err
			}
		}
	} else {
		for _, f := range validSrcFiles {
			err = c.fetchFileOrDir(ftpC, f, dstDir, host.Host)
			if err != nil {
				return "", err
			}
		}
	}

	hasOrHave := "has"
	if len(validSrcFiles) > 1 {
		hasOrHave = "have"
	}

	ret := ""
	if len(notExistSrcFiles) != 0 && len(noPermSrcFiles) != 0 {
		ret = fmt.Sprintf("'%s' %s been copied to '%s'; '%s' not exist; '%s' no permission",
			strings.Join(validSrcFiles, ","),
			hasOrHave,
			dstDir,
			strings.Join(notExistSrcFiles, ","),
			strings.Join(noPermSrcFiles, ","),
		)
	} else if len(notExistSrcFiles) != 0 {
		ret = fmt.Sprintf("'%s' %s been copied to '%s'; '%s' not exist",
			strings.Join(validSrcFiles, ","),
			hasOrHave,
			dstDir,
			strings.Join(notExistSrcFiles, ","),
		)
	} else if len(noPermSrcFiles) != 0 {
		ret = fmt.Sprintf("'%s' %s been copied to '%s'; '%s' no permission",
			strings.Join(validSrcFiles, ","),
			hasOrHave,
			dstDir,
			strings.Join(noPermSrcFiles, ","),
		)
	} else {
		ret = fmt.Sprintf(
			"'%s' %s been copied to '%s'",
			strings.Join(validSrcFiles, ","),
			hasOrHave,
			dstDir,
		)
	}

	return ret, nil
}

func (c *Client) executeCmd(session *ssh.Session, command string, host *Host) (string, error) {
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 28800,
		ssh.TTY_OP_OSPEED: 28800,
	}

	//nolint:gomnd
	if err := session.RequestPty("xterm", 100, 100, modes); err != nil {
		return "", err
	}

	w, err := session.StdinPipe()
	if err != nil {
		return "", err
	}

	r, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	out, isWrongPass := c.handleOutput(w, r, host.Password)

	done := make(chan struct{})
	go func() {
		defer close(done)
		err = session.Run(command)
	}()

	var output []byte
	for v := range out {
		output = append(output, v...)
	}

	outputStr := string(output)

	if <-isWrongPass {
		return "", errors.New("wrong sudo password")
	}

	<-done

	if err != nil {
		log.Debugf("%s: execute command '%s' failed, error: %v, output: %s", host.Host, command, err, outputStr)
		return "", errors.New(outputStr)
	}
	log.Debugf("%s: execute command '%s' success, output: %s", host.Host, command, outputStr)

	return outputStr, nil
}

func (c *Client) getClient(host *Host) (*ssh.Client, error) {
	var (
		client *ssh.Client
		err    error
	)

	sshConfig := &ssh.ClientConfig{
		User:    host.User,
		Auth:    host.SSHAuths,
		Timeout: c.ConnTimeout,
	}
	//nolint:gosec
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	remoteHost := net.JoinHostPort(host.Host, strconv.Itoa(host.Port))

	if c.Proxy.SSHClient != nil || c.Proxy.Err != nil {
		if c.Proxy.Err != nil {
			return nil, c.Proxy.Err
		}

		conn, err2 := c.Proxy.SSHClient.Dial("tcp", remoteHost)
		if err2 != nil {
			return nil, err2
		}

		ncc, chans, reqs, err3 := ssh.NewClientConn(conn, remoteHost, sshConfig)
		if err3 != nil {
			return nil, err3
		}

		client = ssh.NewClient(ncc, chans, reqs)
	} else {
		client, err = ssh.Dial("tcp", remoteHost, sshConfig)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// handle output stream, and give sudo password if necessary.
func (c *Client) handleOutput(w io.Writer, r io.Reader, password string) (<-chan []byte, <-chan bool) {
	out := make(chan []byte, 1)
	isWrongPass := make(chan bool, 1)

	go func() {
		sudoTimes := 0

		for {
			//nolint:gomnd
			buf := make([]byte, 2048)
			n, err := r.Read(buf)
			if err != nil {
				isWrongPass <- false
				close(out)
				return
			}

			if s := string(buf); strings.Contains(s, "[sudo]") {
				sudoTimes++

				if sudoTimes == 1 {
					if _, err := w.Write([]byte(password + "\n")); err != nil {
						isWrongPass <- false
						close(out)
						return
					}
				} else {
					isWrongPass <- true
					close(out)
					return
				}
			}

			out <- buf[:n]
		}
	}()

	return out, isWrongPass
}

// WithConnTimeout ssh connection timeout option.
func WithConnTimeout(timeout time.Duration) func(*Client) {
	return func(c *Client) {
		c.ConnTimeout = timeout
	}
}

// WithCommandTimeout task connection timeout option.
func WithCommandTimeout(timeout time.Duration) func(*Client) {
	return func(c *Client) {
		c.CommandTimeout = timeout
	}
}

// WithConcurrency concurrency tasks number option.
func WithConcurrency(count int) func(*Client) {
	return func(c *Client) {
		c.Concurrency = count
	}
}

// WithProxyServer connect remote hosts by proxy server.
func WithProxyServer(proxyServer, user string, port int, auths []ssh.AuthMethod) func(*Client) {
	return func(c *Client) {
		proxySSHConfig := &ssh.ClientConfig{
			User:    user,
			Auth:    auths,
			Timeout: c.ConnTimeout,
		}
		//nolint:gosec
		proxySSHConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

		proxyClient, err1 := ssh.Dial(
			"tcp",
			net.JoinHostPort(proxyServer, strconv.Itoa(port)),
			proxySSHConfig,
		)
		if err1 != nil {
			c.Proxy.Err = fmt.Errorf("connect to proxy %s:%d failed: %s", proxyServer, port, err1)

			return
		}

		c.Proxy.SSHClient = proxyClient
	}
}
