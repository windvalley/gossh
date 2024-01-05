package batchssh

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

const (
	PushBeginFile      = "C"
	PushBeginFolder    = "D"
	PushBeginEndFolder = "0"
	PushEndFolder      = "E"
	PushEnd            = "\x00"
)

func (c *Client) pushFileOrDirV2(
	client *ssh.Client,
	ftpC *sftp.Client,
	srcFile, dstDir, host string,
	allowOverwrite bool,
) error {
	if !allowOverwrite {
		dstFile := path.Join(dstDir, filepath.Base(srcFile))
		if err := checkAllowOverWrite(ftpC, host, dstFile); err != nil {
			return err
		}
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if !util.IsDir(srcFile) {
		return pushFileV2(session, srcFile, dstDir, host)
	}

	return pushDirV2(session, srcFile, dstDir, host)
}

func pushFileV2(session *ssh.Session, src, dest, host string) error {
	go func() {
		w, err := session.StdinPipe()
		if err != nil {
			log.Debugf("%s: failed to open stdin, error: %v", host, err)
			return
		}
		defer w.Close()

		fileinfo, err := os.Stat(src)
		if err != nil {
			log.Debugf("%s: failed to get file stat, file: %s, error: %v", host, src, err)
			return
		}

		if err := createFile(w, host, src, fileinfo); err != nil {
			log.Debugf("%s: failed to create file, file: %s, error: %v", host, src, err)
		}
	}()

	return session.Run("scp -rt " + dest)
}

func pushDirV2(session *ssh.Session, src, dest, host string) error {
	go func() {
		w, err := session.StdinPipe()
		if err != nil {
			log.Debugf("%s: failed to open stdin, error: %v", host, err)
			return
		}
		defer w.Close()

		fileinfo, err := os.Stat(src)
		if err != nil {
			log.Debugf("%s: failed to get file stat, file: %s, error: %v", host, src, err)
			return
		}

		fmt.Fprintln(w, PushBeginFolder+getMode(fileinfo), PushBeginEndFolder, fileinfo.Name())

		if err := walkDir(w, src, host); err != nil {
			log.Debugf("%s: failed to walk dir, dir: %s, error: %v", host, src, err)
			return
		}

		fmt.Fprintln(w, PushEndFolder)
	}()

	return session.Run("scp -rt " + dest)
}

func walkDir(w io.WriteCloser, dir, host string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		name := file.Name()
		path := path.Join(dir, name)

		fileinfo, err := file.Info()
		if err != nil {
			return err
		}

		if file.IsDir() {
			fmt.Fprintln(w, PushBeginFolder+getMode(fileinfo), PushBeginEndFolder, name)

			if err := walkDir(w, path, host); err != nil {
				return err
			}

			fmt.Fprintln(w, PushEndFolder)
		} else {
			if err := createFile(w, host, path, fileinfo); err != nil {
				return err
			}
		}
	}

	return nil
}

func createFile(w io.WriteCloser, host, path string, fileinfo fs.FileInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(w, PushBeginFile+getMode(fileinfo), fileinfo.Size(), fileinfo.Name())

	if _, err := io.Copy(w, f); err != nil {
		return err
	}

	fmt.Fprint(w, PushEnd)

	log.Debugf("%s: %s pushed", host, path)

	return nil
}

func getMode(f fs.FileInfo) string {
	mod := f.Mode()
	if mod > (1 << 9) {
		mod = mod % (1 << 9)
	}

	return fmt.Sprintf("%#o", uint32(mod))
}

func checkAllowOverWrite(ftpC *sftp.Client, host, dstFile string) error {
	f, err := ftpC.Stat(dstFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%s: failed to stat %s, error: %v", host, dstFile, err)
	}

	if f != nil {
		return fmt.Errorf(
			"%s: %s alreay exists, you can add '-F' flag to overwrite it",
			host,
			dstFile,
		)
	}

	return nil
}
