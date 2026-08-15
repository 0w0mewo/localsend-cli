package localsend

import (
	"encoding/json"
	"net"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/localsend/send"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func GetDeviceInfo(httpclient *fasthttp.Client, ip string, https bool) (models.DeviceInfo, error) {
	remoteAddr := net.JoinHostPort(ip, "53317")

	scheme := "http"
	if https {
		scheme = "https"
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.URI().SetScheme(scheme)
	req.URI().SetHost(remoteAddr)
	req.URI().SetPath(constants.PeerInfoPath)
	req.Header.SetMethod(fiber.MethodGet)

	err := httpclient.Do(req, resp)
	if err != nil {
		return models.DeviceInfo{}, nil
	}

	err = constants.ParseError(resp.StatusCode())
	if err != nil {
		return models.DeviceInfo{}, err
	}

	var res models.DeviceInfo
	err = json.Unmarshal(resp.Body(), &res)
	if err != nil {
		return models.DeviceInfo{}, err
	}
	res.IP = ip

	return res, nil
}

func NewFileSender(httpclient *fasthttp.Client, useDownloadAPI ...bool) send.FileSender {
	if len(useDownloadAPI) > 0 {
		if useDownloadAPI[0] {
			return send.NewReverseSender()
		}
	}
	return send.NewForwardSender(httpclient)
}
