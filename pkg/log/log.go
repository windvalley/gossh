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
	"fmt"
	"io"
	"os"
)

// User can directly use package level functions
var (
	Debugf = std.Debugf
	Infof  = std.Infof
	Warnf  = std.Warnf
	Errorf = std.Errorf

	WithFields = std.WithFields
)

// std global
var std = New()

// Init log
func Init(logfile string, json, verbose, quiet, condense bool) {
	if verbose {
		std.Verbose = true
	}

	if json {
		std.JSONFormat = true
	}

	if condense {
		std.Condense = true
	}

	if logfile != "" {
		//nolint:gomnd
		file, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("Failed to log to '%s'\n", logfile)
			if quiet {
				std.Out = io.Discard
			}
		} else {
			if !quiet {
				mw := io.MultiWriter(os.Stdout, file)
				std.Out = mw
			} else {
				std.Out = file
			}
		}
	} else {
		if quiet {
			std.Out = io.Discard
		}
	}
}
