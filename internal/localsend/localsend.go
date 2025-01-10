package localsend

import (
	"encoding/json"
	"net"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/localsend/send"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/gofiber/fiber/v2"
)

func GetDeviceInfo(ip string) (models.DeviceInfo, error) {
	remoteAddr := net.JoinHostPort(ip, "53317")

	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	req := agent.Request()
	req.URI().SetScheme("https")
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
