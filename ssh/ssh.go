package ssh

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	Port           int
	ConnTimeout    time.Duration
	CommandTimeout time.Duration
	Concurrency    int
}

// NewClient session
func NewClient(user, password string, options ...func(*Client)) *Client {
	client := Client{
		User:           user,
		Password:       password,
		Port:           22,
		ConnTimeout:    10 * time.Second,
		CommandTimeout: 0, // default no timeout
		Concurrency:    100,
	}

	for _, option := range options {
		option(&client)
	}

	return &client
}

// BatchRun command on remote servers
func (c *Client) BatchRun(addrs []string, command string) <-chan *Result {
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
		go func() {
			for addr := range addrCh {
				var result *Result
				output, err := c.Run(addr, command)
				if err != nil {
					result = &Result{addr, "Failed", err.Error()}
				} else {
					result = &Result{addr, "Success", output}
				}
				resCh <- result
			}

			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	return resCh
}

// Run command on remote server
func (c *Client) Run(addr, command string) (string, error) {
	client, session, err := c.getClientSession(addr)
	if err != nil {
		return "", err
	}
	defer client.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 28800,
		ssh.TTY_OP_OSPEED: 28800,
	}

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
	}

	var output []byte
	for v := range out {
		output = append(output, v...)
	}

	outputStr := string(output)
	if err != nil {
		return outputStr, errors.New(outputStr)
	}

	return outputStr, nil
}

func (c *Client) getClientSession(addr string) (*ssh.Client, *ssh.Session, error) {
	sshConfig := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{ssh.Password(c.Password)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshConfig.Timeout = c.ConnTimeout

	client, err := ssh.Dial("tcp", addr+":"+strconv.Itoa(c.Port), sshConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}

	return client, session, nil
}

// handle output stream, and give sudo password if necessary.
func (c *Client) handleOutput(w io.Writer, r io.Reader) <-chan []byte {
	out := make(chan []byte, 1)

	go func() {
		for {
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
