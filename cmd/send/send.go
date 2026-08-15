package send

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"os"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

var (
	ip             string
	files          []string
	supportHttps   bool
	pin            string
	useDownloadAPI bool
)

var Cmd = &cobra.Command{
	Use:   "send [files]...",
	Short: "Send files to localsend instance",
	Long:  "Send files to localsend instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ip == "" && !useDownloadAPI {
			return errors.New("IP address is required")
		}
		files = append(files, args...)
		if len(files) == 0 {
			return errors.New("File is required")
		}

		// generate a temporary certificate to pet the offical app
		cert, err := lsutils.LoadOrGenTempTLScert()
		if err != nil {
			return err
		}
		fingerprint := utils.SHA256ofCert(cert.Leaf)

		// http client that skips certificate verification and presents client side cert
		httpclient := &fasthttp.Client{
			NoDefaultUserAgentHeader: true,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
			},
		}

		// sender device info
		var target models.DeviceInfo
		target = models.NewDeviceInfo(lsutils.GenAlias(), fingerprint)
		target.IP = ip // populate the IP address because the file sender needs it

		sender := localsend.NewFileSender(httpclient, useDownloadAPI)
		sender.SetPIN(pin)
		sender.Init(&target, supportHttps)

		// try to add every file
		for _, file := range files {
			finfo, err := os.Stat(file)
			if err != nil {
				slog.Error("Fail to probe file", "file", file, "error", err)
				continue
			}
			if finfo.IsDir() {
				err = sender.AddDir(file)
				if err != nil {
					slog.Error("Fail to add dir, skipping...", "dir", file, "error", err)
					continue
				}
			} else {
				err = sender.AddFile(file)
				if err != nil {
					slog.Error("Fail to add file, skipping...", "file", file, "error", err)
					continue

				}
			}
			slog.Info("Start sending", "file", file)
		}

		go func() {
			<-utils.WaitForSignal()

			slog.Info("Abort")
			err := sender.Cancel()
			if err != nil {
				slog.Error("Fail to cancel", "error", err)
				return
			}
		}()

		err = sender.Start()
		if err != nil {
			slog.Error("Fail to send", "error", err)
			return nil
		}

		slog.Info("Done")
		return nil
	},
}

func init() {
	Cmd.PersistentFlags().StringVar(&ip, "ip", "", "IP address of remote localsend instance")
	Cmd.PersistentFlags().StringSliceVarP(&files, "file", "f", []string{}, "File/Directory to be sent")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
	Cmd.PersistentFlags().BoolVar(&useDownloadAPI, "dapi", false, "Use Download API(Reverse File Transfer)")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
}
