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

package log

import (
	"io"
	"os"
)

type exitFunc func(int)

// Fields ...
type Fields map[string]interface{}

// Logger ...
type Logger struct {
	Out        io.Writer
	Verbose    bool
	JSONFormat bool
	Condense   bool
	ExitFunc   exitFunc
}

// New logger
func New() *Logger {
	return &Logger{
		Out:        os.Stdout,
		Verbose:    false,
		JSONFormat: false,
		Condense:   false,
		ExitFunc:   os.Exit,
	}
}

// WithFields ...
func (l *Logger) WithFields(fields Fields) *entry {
	entry := newEntry(l)
	entry.Data = fields
	return entry
}

// Debugf ...
func (l *Logger) Debugf(format string, args ...interface{}) {
	entry := newEntry(l)
	entry.Debugf(format, args...)
}

// Infof ...
func (l *Logger) Infof(format string, args ...interface{}) {
	entry := newEntry(l)
	entry.Infof(format, args...)
}

// Warnf ...
func (l *Logger) Warnf(format string, args ...interface{}) {
	entry := newEntry(l)
	entry.Warnf(format, args...)
}

// Errorf ...
func (l *Logger) Errorf(format string, args ...interface{}) {
	entry := newEntry(l)
	entry.Errorf(format, args...)
}
