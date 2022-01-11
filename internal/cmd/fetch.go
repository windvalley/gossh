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
	"github.com/spf13/cobra"

	"github.com/windvalley/gossh/internal/pkg/sshtask"
	"github.com/windvalley/gossh/pkg/util"
)

var (
	srcFiles    []string
	localDstDir string
	tmpDir      string
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Copy files/dirs from target hosts to local",
	Long: `
Copy files/dirs from target hosts to local.`,
	Example: `
  # Copy host1:/path/foo to local /tmp/backup/host1/path/foo.
  $ gossh fetch host1 -f /path/foo -d /tmp/backup

  # Copy files and dirs from target hosts to local dir /tmp/backup/,
  # and files in local dir /tmp/backup/ would be:
  #    /tmp/backup/host1/path1/foo.txt
  #    /tmp/backup/host1/path2/bar/
  #    /tmp/backup/host2/path1/foo.txt
  #    /tmp/backup/host2/path2/bar/
  #
  $ gossh fetch host1 host2 -f /path1/foo.txt -f /path2/bar/ -d /tmp/backup
    or
  $ gossh fetch host1 host2 -f /path1/foo.txt,/path2/bar/ -d /tmp/backup

  # Specify tmp dir on target host instead of default /tmp by flag '-t'.
  # NOTE: If the tmp dir not exist, it will auto create it.
  $ gossh fetch host1 -f /path/foo.txt -d ./backup/ -t /home/user/tmp/

  # Use sudo as root to copy no permission files.
  $ gossh fetch host1 -f /root/foo.txt -d ./backup/ -s

  # Use sudo as 'zhangsan' to copy no permission files.
  $ gossh fetch host1 -f /home/zhangsan/foo.txt -d ./backup -s -U zhangsan`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if errs := config.Validate(); len(errs) != 0 {
			util.CheckErr(errs)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		task := sshtask.NewTask(sshtask.FetchTask, config)

		task.SetTargetHosts(args)
		task.SetFetchFiles(srcFiles)
		task.SetFetchOptions(localDstDir, tmpDir)

		task.Start()
	},
}

func init() {
	rootCmd.AddCommand(fetchCmd)

	fetchCmd.Flags().StringSliceVarP(&srcFiles, "files", "f", nil,
		"files/dirs on target hosts that to be copied",
	)

	fetchCmd.Flags().StringVarP(&localDstDir, "dest-path", "d", "",
		"local directory that files/dirs from target hosts will be copied to",
	)

	fetchCmd.Flags().StringVarP(&tmpDir, "tmp-dir", "t", "/tmp",
		"directory of target hosts for storing temporary zip file",
	)
}
