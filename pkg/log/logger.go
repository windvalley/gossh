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
	ExitFunc   exitFunc
}

// New logger
func New() *Logger {
	return &Logger{
		Out:        os.Stdout,
		Verbose:    false,
		JSONFormat: false,
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
