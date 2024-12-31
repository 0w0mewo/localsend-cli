package models

import (
	"mime"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/utils"
)

type FileMeta struct {
	Id       string `json:"id"`
	Filename string `json:"fileName"`
	Size     int64  `json:"size"`
	FileMIME string `json:"fileType"`
	Checksum string `json:"sha256"`
	FullPath string `json:"-"`
}

func GenFileMeta(fpath string) (FileMeta, error) {
	fd, err := os.Stat(fpath)
	if err != nil {
		return FileMeta{}, err
	}

	checksum, err := utils.SHA256ofFile(fpath)
	if err != nil {
		return FileMeta{}, err
	}

	fileType := mime.TypeByExtension(filepath.Ext(fpath))
	if fileType == "" {
		fileType = "text/plain"
	}

	return FileMeta{
		Id:       fd.Name(),
		Filename: fd.Name(),
		Size:     fd.Size(),
		FileMIME: fileType,
		Checksum: checksum,
		FullPath: fpath,
	}, nil
}
