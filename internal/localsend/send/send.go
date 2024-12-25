package send

import "github.com/0w0mewo/localsend-cli/internal/models"

type FileSender interface {
	SetPIN(pin string)
	Init(target *models.DeviceInfo, https bool) error
	AddFile(filePath string) error
	AddDir(dirPath string) error
	Start() error
	Cancel() error
}
