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
func Init(logfile string, json, verbose, quiet bool) {
	if verbose {
		std.Verbose = true
	}

	if json {
		std.JSONFormat = true
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
