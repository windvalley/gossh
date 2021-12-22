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

package util

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Zip a dir or file.
func Zip(pathToZip, zipName string) error {
	file, err := os.Create(zipName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	w := zip.NewWriter(file)
	defer w.Close()

	err = filepath.Walk(pathToZip, func(fullpathFile string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relativePath := "./" + strings.TrimPrefix(fullpathFile, filepath.Dir(pathToZip))

		srcFile, err := os.Open(fullpathFile)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		fileInfo, err := srcFile.Stat()
		if err != nil {
			return err
		}

		fileHeader, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return err
		}

		// Using FileInfoHeader() above only uses the basename of the file. If we want
		// to preserve the folder structure we can overwrite this with the relativePath.
		fileHeader.Name = relativePath

		// Change to deflate to gain better compression.
		// See http://golang.org/pkg/archive/zip/#pkg-constants
		fileHeader.Method = zip.Deflate

		zipFile, err := w.CreateHeader(fileHeader)
		if err != nil {
			return err
		}

		_, err = io.Copy(zipFile, srcFile)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

// Unzip a zip file.
func Unzip(zipName, dstDir string) error {
	archive, err := zip.OpenReader(zipName)
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, f := range archive.File {
		//nolint:gosec
		filePath := filepath.Join(dstDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return err
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer dstFile.Close()

		file, err := f.Open()
		if err != nil {
			return err
		}
		defer file.Close()

		//nolint:gosec
		_, err = io.Copy(dstFile, file)
		if err != nil {
			return err
		}
	}

	return nil
}
