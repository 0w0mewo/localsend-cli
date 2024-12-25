package localsend

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/localsend/send"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
)

func GetDeviceInfo(ip string) (models.DeviceInfo, error) {
	remoteAddr := net.JoinHostPort(ip, "53317")
	base := filepath.Join(remoteAddr, constants.InfoPath)
	url := fmt.Sprintf("https://%s", base)

	resp, err := lsutils.HttpClient.Get(url)
	if err != nil {
		return models.DeviceInfo{}, err
	}

	err = constants.ParseError(resp.StatusCode)
	if err != nil {
		return models.DeviceInfo{}, err
	}
	defer resp.Body.Close()

	var res models.DeviceInfo
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return models.DeviceInfo{}, err
	}
	res.IP = ip

	return res, nil
}

func NewFileSender() send.FileSender {
	return send.NewForwardSender()
}
