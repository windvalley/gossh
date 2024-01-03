package batchssh

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/windvalley/gossh/pkg/log"
)

// pushFileOrDir is less efficient than pushFileOrDirV2.
//
//nolint:unused
func (c *Client) pushFileOrDir(
	ftpC *sftp.Client,
	srcFile, dstDir, host string,
	allowOverwrite bool,
) error {
	if !isDir(srcFile) {
		_, err := c.pushFile(ftpC, srcFile, dstDir, host, allowOverwrite)
		if err != nil {
			return err
		}

		return nil
	}

	localFiles, err := os.ReadDir(srcFile)
	if err != nil {
		return fmt.Errorf("read dir '%s' failed: %w", srcFile, err)
	}

	remoteFilePath := path.Join(dstDir, filepath.Base(srcFile))
	err = ftpC.MkdirAll(remoteFilePath)
	if err != nil {
		log.Errorf("%s: mkdir '%s' failed", host, remoteFilePath)
		return err
	}

	for _, item := range localFiles {
		localFilePath := path.Join(srcFile, item.Name())

		if item.IsDir() {
			err = c.pushFileOrDir(ftpC, localFilePath, remoteFilePath, host, allowOverwrite)
			if err != nil {
				log.Errorf("%s: pushFileOrDir '%s' failed", host, localFilePath)
				return err
			}
		} else {
			_, err = c.pushFile(ftpC, localFilePath, remoteFilePath, host, allowOverwrite)
			if err != nil {
				log.Errorf("%s: pushFile '%s' failed", host, localFilePath)
				return err
			}
		}
	}

	return nil
}

func (c *Client) pushFile(
	ftpC *sftp.Client,
	srcFile, dstDir, host string,
	allowOverwrite bool,
) (*sftp.File, error) {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(srcFile, "~/") {
		srcFile = strings.Replace(srcFile, "~", homeDir, 1)
	}

	content, err := os.ReadFile(srcFile)
	if err != nil {
		return nil, err
	}

	fileStat, err := os.Stat(srcFile)
	if err != nil {
		return nil, err
	}

	srcFileBasename := filepath.Base(srcFile)
	dstFile := path.Join(dstDir, srcFileBasename)

	if !allowOverwrite {
		err = checkAllowOverWrite(ftpC, host, dstFile)
		if err != nil {
			return nil, err
		}
	}

	file, err := ftpC.Create(dstFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("dest dir '%s' not exist", dstDir)
		}

		if err, ok := err.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
			return nil, fmt.Errorf("no permission to write to dest dir '%s'", dstDir)
		}

		return nil, err
	}

	_, err = file.Write(content)
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(fileStat.Mode()); err != nil {
		return nil, err
	}

	if err := ftpC.Chtimes(dstFile, time.Now(), fileStat.ModTime()); err != nil {
		return nil, err
	}

	log.Debugf("%s: '%s' -> '%s", host, srcFile, dstFile)

	return file, nil
}
