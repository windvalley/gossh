package batchssh

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/windvalley/gossh/pkg/log"
	"github.com/windvalley/gossh/pkg/util"
)

func (c *Client) fetchFileWithZip(
	client *ssh.Client,
	ftpC *sftp.Client,
	srcFile string,
	dstDir, tmpDir, runAs string,
	host *Host,
) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	zippedFileTmpDir := path.Join(tmpDir, ".gossh-tmp-"+host.Host)
	tmpZipFile := fmt.Sprintf("%s.%d", host.Host, time.Now().UnixMicro())
	zippedFileFullpath := path.Join(zippedFileTmpDir, tmpZipFile)

	srcFileDir := filepath.Dir(srcFile)
	srcFileName := filepath.Base(srcFile)

	log.Debugf("%s: start to zip '%s'", host.Host, srcFile)

	timeStart := time.Now()

	_, err = c.executeCmd(
		session,
		fmt.Sprintf(
			`if which zip &>/dev/null;then 
    sudo -u %s -H bash -c '[[ ! -d %s ]] && { mkdir -p %s;chmod 777 %s;}; cd %s; zip -r %s %s'
else
	echo "need install 'zip' command"
	exit 1
fi`,
			runAs,
			zippedFileTmpDir,
			zippedFileTmpDir,
			zippedFileTmpDir,
			srcFileDir,
			zippedFileFullpath,
			srcFileName,
		),
		host,
	)
	if err != nil {
		return fmt.Errorf("%s: zip '%s' failed: %s", host.Host, srcFile, err)
	}

	log.Debugf("%s: zip '%s' cost %s", host.Host, srcFile, time.Since(timeStart))

	if err = fetchZipFile(ftpC, zippedFileFullpath, dstDir); err != nil {
		return fmt.Errorf("%s: fetch zip file '%s' failed: %s", host.Host, zippedFileFullpath, err)
	}
	log.Debugf("%s: fetched zip file '%s'", host.Host, zippedFileFullpath)

	session2, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session2.Close()

	_, err = c.executeCmd(
		session2,
		fmt.Sprintf("sudo -u %s -H bash -c 'rm -f %s'", runAs, zippedFileFullpath),
		host,
	)
	if err != nil {
		return fmt.Errorf("%s: remove '%s' failed: %s", host.Host, zippedFileFullpath, err)
	}
	log.Debugf("%s: removed '%s'", host.Host, zippedFileFullpath)

	localZippedFileFullpath := path.Join(dstDir, tmpZipFile)
	defer func() {
		if err := os.Remove(localZippedFileFullpath); err != nil {
			log.Debugf("remove '%s' failed: %s", localZippedFileFullpath, err)
		} else {
			log.Debugf("removed '%s'", localZippedFileFullpath)
		}
	}()
	if err := util.Unzip(localZippedFileFullpath, dstDir); err != nil {
		return fmt.Errorf("unzip '%s' to '%s' failed: %s", localZippedFileFullpath, dstDir, err)
	}
	log.Debugf("unzipped '%s' to '%s'", localZippedFileFullpath, dstDir)

	return nil
}

func fetchZipFile(
	ftpC *sftp.Client,
	srcZipFile, dstDir string,
) error {
	srcZipFileName := filepath.Base(srcZipFile)
	dstZipFile := path.Join(dstDir, srcZipFileName)

	file, err := ftpC.Open(srcZipFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("'%s' not exist", srcZipFile)
		}

		if err, ok := err.(*sftp.StatusError); ok && err.Code == uint32(sftp.ErrSshFxPermissionDenied) {
			return fmt.Errorf("no permission to open '%s'", srcZipFile)
		}

		return err
	}
	defer file.Close()

	zipFile, err := os.Create(dstZipFile)
	if err != nil {
		return fmt.Errorf("create local '%s' failed: %w", dstZipFile, err)
	}
	defer zipFile.Close()

	_, err = file.WriteTo(zipFile)
	if err != nil {
		return err
	}

	return nil
}
