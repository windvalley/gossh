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

package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/windvalley/gossh/internal/cmd/vault"
	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

const cfgFileFlag = "config"

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gossh",
	Short: "A high-performance and high-concurrency ssh tool",
	Long: `
Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands or a local script on target hosts,
push files and dirs to target hosts, and fetch files and dirs from target hosts to local.

Find more information at: https://github.com/windvalley/gossh`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initLogger, printDebugInfo)

	vault.SetHelpFunc(rootCmd)

	util.CobraAddSubCommandInOrder(rootCmd,
		commandCmd,
		scriptCmd,
		pushCmd,
		fetchCmd,
		vault.Cmd,
		configCmd,
		versionCmd,
	)

	localFlags := rootCmd.Flags()
	persistentFlags := rootCmd.PersistentFlags()

	localFlags.SortFlags = false
	persistentFlags.SortFlags = false

	configFlags := configflags.New()
	configFlags.AddFlagsTo(persistentFlags)

	persistentFlags.StringVarP(&cfgFile, cfgFileFlag, "", "", "config file (default {$PWD,$HOME}/.gossh.yaml)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		util.CheckErr(err)

		// Search the default configuration file.
		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".gossh")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	_ = viper.ReadInConfig()

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		util.CheckErr(err)
	}

	if err := viper.Unmarshal(&configflags.Config); err != nil {
		util.CheckErr(err)
	}

	if err := configflags.Config.Complete(); err != nil {
		util.CheckErr(err)
	}
}

func initLogger() {
	log.Init(
		configflags.Config.Output.File,
		configflags.Config.Output.JSON,
		configflags.Config.Output.Verbose,
		configflags.Config.Output.Quiet,
		configflags.Config.Output.Condense,
	)
}

func printDebugInfo() {
	configFileUsed := viper.ConfigFileUsed()
	if configFileUsed != "" {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	} else {
		log.Debugf("Not using config file")
	}

	log.Debugf("Config contents: %s", configflags.Config.String())
}
