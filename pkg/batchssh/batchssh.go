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
	"io/ioutil"
	"net"
	"os"
	"path"
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

	// SuccessIdentifier ...
	SuccessIdentifier = "SUCCESS"
	// FailedIdentifier ...
	FailedIdentifier = "FAILED"
)

// Task execute command or copy file or execute script
type Task interface {
	RunSSH(addr string) (string, error)
}

// Result of ssh command
type Result struct {
	Addr    string `json:"addr"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Client for ssh
type Client struct {
	User           string
	Password       string
	Auths          []ssh.AuthMethod
	Port           int
	ConnTimeout    time.Duration
	CommandTimeout time.Duration
	Concurrency    int
}

// NewClient session
func NewClient(
	user, password string,
	auths []ssh.AuthMethod,
	options ...func(*Client),
) (*Client, error) {
	log.Debugf("Login user: %s", user)

	client := Client{
		User:           user,
		Password:       password,
		Auths:          auths,
		Port:           22,
		ConnTimeout:    10 * time.Second,
		CommandTimeout: 0,
		Concurrency:    100,
	}

	for _, option := range options {
		option(&client)
	}

	return &client, nil
}

// BatchRun command on remote servers
func (c *Client) BatchRun(
	addrs []string,
	sshTask Task,
) <-chan *Result {
	addrCh := make(chan string)
	go func() {
		defer close(addrCh)
		for _, addr := range addrs {
			addrCh <- addr
		}
	}()

	resCh := make(chan *Result)
	var wg sync.WaitGroup
	wg.Add(c.Concurrency)
	for i := 0; i < c.Concurrency; i++ {
		go func(wg *sync.WaitGroup) {
			for addr := range addrCh {
				var result *Result
				output, err := sshTask.RunSSH(addr)
				if err != nil {
					result = &Result{addr, FailedIdentifier, err.Error()}
				} else {
					result = &Result{addr, SuccessIdentifier, output}
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

// ExecuteCmd on remote host
func (c *Client) ExecuteCmd(addr, command, lang, runAs string, sudo bool) (string, error) {
	client, err := c.getClient(addr)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}

	exportLang := ""
	if lang != "" {
		exportLang = fmt.Sprintf(exportLangPattern, lang, lang, lang)
	}

	if sudo {
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s'", exportLang, runAs, command)
	} else {
		command = exportLang + command
	}

	return c.executeCmd(session, command)
}

// CopyFiles to remote host
func (c *Client) CopyFiles(
	addr string,
	srcFiles, srcZipFiles []string,
	dstDir string,
	allowOverwrite bool,
) (string, error) {
	client, err := c.getClient(addr)
	if err != nil {
		return "", err
	}
	defer client.Close()

	ftpC, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer ftpC.Close()

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

			file, err = c.copyZipFile(ftpC, f, filepath.Base(srcFile), dstDir, allowOverwrite)
			if err == nil {
				file.Close()
			}
		}()

		if c.CommandTimeout > 0 {
			select {
			case <-done:
			case <-time.After(c.CommandTimeout):
				session, err1 := client.NewSession()
				if err1 != nil {
					return "", err
				}
				if _, err2 := c.executeCmd(
					session,
					fmt.Sprintf(
						"cd %s;rm %s;",
						dstDir,
						dstZipFile,
					),
				); err2 != nil {
					return "", err2
				}
				session.Close()

				return "", fmt.Errorf("push '%s' timeout", srcFile)
			}
		} else {
			<-done
		}

		if err != nil {
			return "", err
		}

		session, err := client.NewSession()
		if err != nil {
			return "", err
		}

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
		)
		if err != nil {
			return "", err
		}
		session.Close()
	}

	hasOrHave := "has"
	if len(srcFiles) > 1 {
		hasOrHave = "have"
	}

	return fmt.Sprintf("'%s' %s been copied to '%s'", strings.Join(srcFiles, ","), hasOrHave, dstDir), nil
}

// ExecuteScript on remote host
func (c *Client) ExecuteScript(
	addr, srcFile, dstDir, lang, runAs string,
	sudo, remove, allowOverwrite bool,
) (string, error) {
	client, err := c.getClient(addr)
	if err != nil {
		return "", err
	}
	defer client.Close()

	ftpC, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer ftpC.Close()

	file, err := c.copyFile(ftpC, srcFile, dstDir, allowOverwrite)
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
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s;rm -f %s'", exportLang, runAs, script, script)
	case sudo && !remove:
		command = fmt.Sprintf("%ssudo -u %s -H bash -c '%s'", exportLang, runAs, script)
	case !sudo && remove:
		command = fmt.Sprintf("%s%s;rm -f %s", exportLang, script, script)
	case !sudo && !remove:
		command = exportLang + script
	}

	return c.executeCmd(session, command)
}

func (c *Client) executeCmd(session *ssh.Session, command string) (string, error) {
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

	out := c.handleOutput(w, r)

	done := make(chan struct{})
	go func() {
		defer close(done)
		err = session.Run(command)
	}()

	if c.CommandTimeout > 0 {
		select {
		case <-done:
		case <-time.After(c.CommandTimeout):
			return "", errors.New("command timeout")
		}
	} else {
		<-done
	}

	var output []byte
	for v := range out {
		output = append(output, v...)
	}

	outputStr := string(output)
	if err != nil {
		return "", errors.New(outputStr)
	}

	return outputStr, nil
}

func (c *Client) copyFile(
	ftpC *sftp.Client,
	srcFile, dstDir string,
	allowOverwrite bool,
) (*sftp.File, error) {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(srcFile, "~/") {
		srcFile = strings.Replace(srcFile, "~", homeDir, 1)
	}

	content, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return nil, err
	}

	fileStat, err := os.Stat(srcFile)
	if err != nil {
		return nil, err
	}

	srcFileBaseName := filepath.Base(srcFile)
	dstFile := path.Join(dstDir, srcFileBaseName)

	if !allowOverwrite {
		dstFileInfo, _ := ftpC.Stat(dstFile)
		if dstFileInfo != nil {
			return nil, fmt.Errorf(
				"%s alreay exists, you can add '-F' flag to overwrite it",
				dstFile,
			)
		}
	}

	file, err := ftpC.Create(dstFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("dest dir '%s' not exist", dstDir)
		}

		if err, ok := err.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
			return nil, fmt.Errorf("no permission to write to dest dir '%s'", dstDir)
		}

		return nil, err
	}

	_, err = file.Write(content)
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(fileStat.Mode()); err != nil {
		return nil, err
	}

	if err := ftpC.Chtimes(dstFile, time.Now(), fileStat.ModTime()); err != nil {
		return nil, err
	}

	return file, nil
}

func (c *Client) copyZipFile(
	ftpC *sftp.Client,
	srcZipFile, srcFileName, dstDir string,
	allowOverwrite bool,
) (*sftp.File, error) {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(srcZipFile, "~/") {
		srcZipFile = strings.Replace(srcZipFile, "~", homeDir, 1)
	}

	content, err := ioutil.ReadFile(srcZipFile)
	if err != nil {
		return nil, err
	}

	srcZipFileName := filepath.Base(srcZipFile)
	dstZipFile := path.Join(dstDir, srcZipFileName)

	dstFile := path.Join(dstDir, srcFileName)

	if !allowOverwrite {
		dstFileInfo, _ := ftpC.Stat(dstFile)
		if dstFileInfo != nil {
			return nil, fmt.Errorf(
				"%s alreay exists, you can add '-F' flag to overwrite it",
				dstFile,
			)
		}
	}

	file, err := ftpC.Create(dstZipFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("dest dir '%s' not exist", dstDir)
		}

		if err, ok := err.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
			return nil, fmt.Errorf("no permission to write to dest dir '%s'", dstDir)
		}

		return nil, err
	}

	_, err = file.Write(content)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (c *Client) getClient(addr string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: c.User,
		Auth: c.Auths,
	}

	//nolint:gosec
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshConfig.Timeout = c.ConnTimeout

	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(c.Port)), sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// handle output stream, and give sudo password if necessary.
func (c *Client) handleOutput(w io.Writer, r io.Reader) <-chan []byte {
	out := make(chan []byte, 1)

	go func() {
		for {
			//nolint:gomnd
			buf := make([]byte, 2048)
			n, err := r.Read(buf)
			if err != nil {
				close(out)
				return
			}

			if s := string(buf); strings.Contains(s, "[sudo]") {
				if _, err := w.Write([]byte(c.Password + "\n")); err != nil {
					close(out)
					return
				}
			}

			out <- buf[:n]
		}
	}()

	return out
}

// WithConnTimeout ssh connection timeout option
func WithConnTimeout(timeout time.Duration) func(*Client) {
	return func(s *Client) {
		s.ConnTimeout = timeout
	}
}

// WithCommandTimeout task connection timeout option
func WithCommandTimeout(timeout time.Duration) func(*Client) {
	return func(s *Client) {
		s.CommandTimeout = timeout
	}
}

// WithPort port option
func WithPort(port int) func(*Client) {
	return func(s *Client) {
		s.Port = port
	}
}

// WithConcurrency concurrency tasks number option
func WithConcurrency(count int) func(*Client) {
	return func(s *Client) {
		s.Concurrency = count
	}
}
