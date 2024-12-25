package send

import "github.com/0w0mewo/localsend-cli/internal/models"

type ReverseSender struct{}

func NewReverseSender() *ReverseSender {
	return &ReverseSender{}
}

func (rs *ReverseSender) SetPIN(pin string) {
	panic("not implemented") // TODO: Implement
}

func (rs *ReverseSender) Init(target *models.DeviceInfo, https bool) error {
	panic("not implemented") // TODO: Implement
}

func (rs *ReverseSender) AddFile(filePath string) error {
	panic("not implemented") // TODO: Implement
}

func (rs *ReverseSender) AddDir(dirPath string) error {
	panic("not implemented") // TODO: Implement
}

func (rs *ReverseSender) Start() error {
	panic("not implemented") // TODO: Implement
}

func (rs *ReverseSender) Cancel() error {
	panic("not implemented") // TODO: Implement
}
