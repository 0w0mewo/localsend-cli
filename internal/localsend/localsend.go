package localsend

import (
	"encoding/json"
	"net"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/localsend/send"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/gofiber/fiber/v2"
)

// validDeviceTypes are the allowed deviceType values per protocol spec Section 7.1
var validDeviceTypes = map[string]bool{
	"mobile":   true,
	"desktop":  true,
	"web":      true,
	"headless": true,
	"server":   true,
}

// normalizeDeviceType validates deviceType and falls back to "desktop" for unknown values
// per protocol spec: "The official implementation falls back to desktop"
func normalizeDeviceType(deviceType string) string {
	if validDeviceTypes[deviceType] {
		return deviceType
	}
	return "desktop"
}

func GetDeviceInfo(ip string, https bool) (models.DeviceInfo, error) {
	remoteAddr := net.JoinHostPort(ip, "53317")

	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	scheme := "http"
	if https {
		scheme = "https"
	}

	req := agent.Request()
	req.URI().SetScheme(scheme)
	req.URI().SetHost(remoteAddr)
	req.URI().SetPath(constants.InfoPath)
	req.Header.SetMethod(fiber.MethodGet)
	err := agent.Parse()
	if err != nil {
		return models.DeviceInfo{}, err
	}

	status, b, errs := agent.InsecureSkipVerify().Bytes()
	if len(errs) != 0 {
		return models.DeviceInfo{}, errs[0]
	}
	err = constants.ParseError(status)
	if err != nil {
		return models.DeviceInfo{}, err
	}

	var res models.DeviceInfo
	err = json.Unmarshal(b, &res)
	if err != nil {
		return models.DeviceInfo{}, err
	}
	res.IP = ip
	res.DeviceType = normalizeDeviceType(res.DeviceType)

	return res, nil
}

func NewFileSender(useDownloadAPI ...bool) send.FileSender {
	if len(useDownloadAPI) > 0 {
		if useDownloadAPI[0] {
			return send.NewReverseSender()
		}
	}
	return send.NewForwardSender()
}
