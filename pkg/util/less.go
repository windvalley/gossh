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

package util

import (
	"os"
	"os/exec"
)

// LessContent is like shell command: echo "content" | less
func LessContent(content string) error {
	var err error

	c1 := exec.Command("echo", content)
	c2 := exec.Command("less")

	c2.Stdout = os.Stdout

	c2.Stdin, err = c1.StdoutPipe()
	if err != nil {
		return err
	}

	if err := c2.Start(); err != nil {
		return err
	}

	if err := c1.Run(); err != nil {
		return err
	}

	if err := c2.Wait(); err != nil {
		return err
	}

	return nil
}
