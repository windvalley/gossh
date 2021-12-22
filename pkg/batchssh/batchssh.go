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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/windvalley/gossh/pkg/log"
)

const exportLangPattern = "export LANG=%s;export LC_ALL=%s;export LANGUAGE=%s;"

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
	Auth           []ssh.AuthMethod
	Port           int
	ConnTimeout    time.Duration
	CommandTimeout time.Duration
	Concurrency    int
}

// NewClient session
func NewClient(
	user, password, sshAuthSock string,
	keys []string,
	options ...func(*Client),
) (*Client, error) {
	log.Debugf("Login user: %s", user)

	authMethods, err := buildAuthMethods(password, sshAuthSock, keys)
	if err != nil {
		return nil, err
	}

	client := Client{
		User:           user,
		Password:       password,
		Auth:           authMethods,
		Port:           22,
		ConnTimeout:    10 * time.Second,
		CommandTimeout: 0, // default no timeout
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
					result = &Result{addr, "Failed", err.Error()}
				} else {
					result = &Result{addr, "Success", output}
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

	reg := regexp.MustCompile(`.[0-9]{16}$`)
	for _, f := range srcZipFiles {
		name := filepath.Base(f)

		realName := strings.TrimPrefix(name, ".")
		realName = reg.ReplaceAllString(realName, "")

		file, err := c.copyZipFile(ftpC, f, realName, dstDir, allowOverwrite)
		if err != nil {
			return "", err
		}
		file.Close()

		dstZipFile := filepath.Base(f)
		session, err := client.NewSession()
		if err != nil {
			return "", err
		}

		_, err = c.executeCmd(
			session,
			fmt.Sprintf(
				`which unzip &>/dev/null && { cd %s;unzip -o %s;rm %s;} || 
				{ echo "need install 'unzip' command";exit 1;}`,
				dstDir,
				dstZipFile,
				dstZipFile,
			),
		)
		if err != nil {
			return "", err
		}
		session.Close()
	}

	return fmt.Sprintf("'%s' has been copied to '%s'", strings.Join(srcFiles, ","), dstDir), nil
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
	srcFile, realSrcFileName, dstDir string,
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

	srcFileBaseName := filepath.Base(srcFile)
	dstFile := path.Join(dstDir, srcFileBaseName)

	realDstFile := path.Join(dstDir, realSrcFileName)

	if !allowOverwrite {
		dstFileInfo, _ := ftpC.Stat(realDstFile)
		if dstFileInfo != nil {
			return nil, fmt.Errorf(
				"%s alreay exists, you can add '-F' flag to overwrite it",
				realDstFile,
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

	return file, nil
}

func (c *Client) getClient(addr string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: c.User,
		Auth: c.Auth,
	}

	//nolint:gosec
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshConfig.Timeout = c.ConnTimeout

	client, err := ssh.Dial("tcp", addr+":"+strconv.Itoa(c.Port), sshConfig)
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

func buildAuthMethods(password, sshAuthSock string, keys []string) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod

	if len(keys) != 0 {
		if sshAuthSock != "" {
			log.Debugf("Auth method: use SSH_AUTH_SOCK=%s", sshAuthSock)

			var (
				err           error
				agentUnixSock net.Conn
			)

			for {
				agentUnixSock, err = net.Dial("unix", sshAuthSock)
				if err != nil {
					netErr := err.(net.Error)
					if netErr.Temporary() {
						//nolint:gosec,gomnd
						time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
						continue
					}

					return nil, fmt.Errorf("cannot open connection to SSH Agent: %v ", netErr)
				}

				auth = []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(agentUnixSock).Signers)}

				break
			}

			return auth, nil
		}

		log.Debugf("Auth method: use identity file '%s'", strings.Join(keys, ","))

		signers := makeSigners(keys)
		if len(signers) == 0 {
			return nil, fmt.Errorf("no valid pubkeys")
		}

		auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

		return auth, nil
	}

	log.Debugf("Auth method: use password")

	auth = []ssh.AuthMethod{ssh.Password(password)}

	return auth, nil
}

func makeSigners(keys []string) []ssh.Signer {
	signers := []ssh.Signer{}

	for _, keyname := range keys {
		signer, err := makeSigner(keyname)
		if err == nil {
			signers = append(signers, signer)
		}
	}

	return signers
}

func makeSigner(keyname string) (signer ssh.Signer, err error) {
	fp, err := os.Open(keyname)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("could not parse %s: %v", keyname, err)
		}
		return
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil {
		log.Warnf("could not read %s: %v", keyname, err)
		return
	}

	if bytes.Contains(buf, []byte("ENCRYPTED")) {
		var (
			tmpfp *os.File
		)

		tmpfp, err = ioutil.TempFile("", "key")
		if err != nil {
			log.Warnf("could not create temporary file: %v", err)
			return
		}

		tmpName := tmpfp.Name()

		defer func() { tmpfp.Close(); os.Remove(tmpName) }()

		_, err = tmpfp.Write(buf)
		if err != nil {
			log.Warnf("could not write encrypted key contents to temporary file: %v", err)
			return
		}

		err = tmpfp.Close()
		if err != nil {
			log.Warnf("could not close temporary file: %v", err)
			return
		}

		tmpfp, err = os.Open(tmpName)
		if err != nil {
			return
		}

		buf, err = ioutil.ReadAll(tmpfp)
		if err != nil {
			return
		}

		tmpfp.Close()
		os.Remove(tmpName)
	}

	signer, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		log.Warnf("could not parse %s: %v", keyname, err)
		return
	}

	//nolint:nakedret
	return
}
