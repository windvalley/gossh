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

func pushZipFile(
	ftpC *sftp.Client,
	srcZipFile, srcFileName, dstDir, host string,
	allowOverwrite bool,
) (*sftp.File, error) {
	homeDir := os.Getenv("HOME")
	if strings.HasPrefix(srcZipFile, "~/") {
		srcZipFile = strings.Replace(srcZipFile, "~", homeDir, 1)
	}

	content, err := os.ReadFile(srcZipFile)
	if err != nil {
		return nil, err
	}

	srcZipFileName := filepath.Base(srcZipFile)
	dstZipFile := path.Join(dstDir, srcZipFileName)

	dstFile := path.Join(dstDir, srcFileName)

	if !allowOverwrite {
		err = checkAllowOverWrite(ftpC, host, dstFile)
		if err != nil {
			return nil, err
		}
	}

	file, err := ftpC.Create(dstZipFile)
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

	log.Debugf("%s: zip file '%s' pushed", host, srcZipFile)

	return file, nil
}
