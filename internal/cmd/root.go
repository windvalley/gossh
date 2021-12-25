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

	"github.com/windvalley/gossh/internal/pkg/configflags"
	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

const cfgFileFlag = "config"

var (
	cfgFile string
	config  *configflags.ConfigFlags
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gossh",
	Short: "A high-performance and high-concurrency ssh tool",
	Long: `
Gossh is a high-performance and high-concurrency ssh tool.
This tool can efficiently manage tens of thousands of Linux server clusters.
It can efficiently execute commands or a local script on remote servers,
and transfer files and dirs to remote servers.

Find more information at: https://github.com/windvalley/gossh`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initLogger, printDebugInfo)

	persistentFlags := rootCmd.PersistentFlags()

	persistentFlags.StringVarP(&cfgFile, cfgFileFlag, "", "", "config file (default is $HOME/.gossh.yaml)")

	configFlags := configflags.New()
	configFlags.AddFlagsTo(persistentFlags)
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

		// Search config in home directory with name ".gossh" (without extension).
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

	if err := viper.Unmarshal(&config); err != nil {
		util.CheckErr(err)
	}

	if err := config.Complete(); err != nil {
		util.CheckErr(err)
	}
}

func initLogger() {
	log.Init(
		config.Output.File,
		config.Output.JSON,
		config.Output.Verbose,
		config.Output.Quiet,
	)
}

func printDebugInfo() {
	configFileUsed := viper.ConfigFileUsed()
	if configFileUsed != "" {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	} else {
		log.Debugf("Not using config file")
	}

	log.Debugf("Config contents: %s", config.String())
}
