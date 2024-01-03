package batchssh

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"

	"github.com/windvalley/gossh/pkg/log"
)

func (c *Client) fetchFileOrDir(
	ftpC *sftp.Client,
	srcFile, dstDir, host string,
) error {
	fStat, err := ftpC.Stat(srcFile)
	if err != nil {
		log.Errorf("%s: stat '%s' failed: %v", host, srcFile, err)
		return err
	}

	if !fStat.IsDir() {
		err = fetchFile(ftpC, srcFile, dstDir, host)
		if err != nil {
			return err
		}

		return nil
	}

	remoteFiles, err := ftpC.ReadDir(srcFile)
	if err != nil {
		return fmt.Errorf("%s: read dir '%s' failed: %w", host, srcFile, err)
	}

	localFilePath := path.Join(dstDir, filepath.Base(srcFile))
	err = os.MkdirAll(localFilePath, fStat.Mode().Perm())
	if err != nil {
		log.Errorf("make local dir '%s' failed: %v", localFilePath, err)
		return err
	}
	log.Debugf("make local dir '%s'", localFilePath)

	for _, item := range remoteFiles {
		remoteFilePath := path.Join(srcFile, item.Name())

		if item.IsDir() {
			err = c.fetchFileOrDir(ftpC, remoteFilePath, localFilePath, host)
			if err != nil {
				log.Errorf("%s: fetchFileOrDir '%s' failed, error: %v", host, remoteFilePath, err)
				return err
			}
		} else {
			err = fetchFile(ftpC, remoteFilePath, localFilePath, host)
			if err != nil {
				log.Errorf("%s: fetchFile '%s' failed, error: %v", host, localFilePath, err)
				return err
			}
		}
	}

	return nil
}

func fetchFile(
	ftpC *sftp.Client,
	srcFile, dstDir, host string,
) error {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(srcFile, "~/") {
		srcFile = strings.Replace(srcFile, "~", homeDir, 1)
	}

	remoteFile, err := ftpC.Open(srcFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("'%s' not exist", srcFile)
		}

		if err, ok := err.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
			return fmt.Errorf("no permission to open '%s'", srcFile)
		}

		return err
	}
	defer remoteFile.Close()

	stat, err := remoteFile.Stat()
	if err != nil {
		return fmt.Errorf("%s: stat remote file '%s' failed: %w", host, srcFile, err)
	}

	srcFileBasename := filepath.Base(srcFile)
	dstFile := path.Join(dstDir, srcFileBasename)

	localFile, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("create local file '%s' failed: %w", dstFile, err)
	}
	defer localFile.Close()

	_, err = remoteFile.WriteTo(localFile)
	if err != nil {
		return fmt.Errorf("write content to local file '%s' failed: %w", dstFile, err)
	}

	if err := localFile.Chmod(stat.Mode()); err != nil {
		return fmt.Errorf("chmod local file '%s' failed: %w", dstFile, err)
	}

	log.Debugf("%s: '%s' -> '%s fetched", host, srcFile, dstFile)

	return nil
}
