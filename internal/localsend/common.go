package localsend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend/errors"
	"github.com/0w0mewo/localsend-cli/internal/models"
)

const (
	UploadPath    = "/api/localsend/v2/upload"
	PreuploadPath = "/api/localsend/v2/prepare-upload"
	CancelPath    = "/api/localsend/v2/cancel"
	InfoPath      = "/api/localsend/v2/info"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func genTLScert() (tls.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "LocalSend User",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}
	pubkey := privkey.Public()

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, privkey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPrivKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	})

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return tls.X509KeyPair(certPem, certPrivKeyPem)
}

func GetDeviceInfo(ip string) (models.DeviceInfo, error) {
	remoteAddr := net.JoinHostPort(ip, "53317")
	base := filepath.Join(remoteAddr, InfoPath)
	url := fmt.Sprintf("https://%s", base)

	resp, err := httpClient.Get(url)
	if err != nil {
		return models.DeviceInfo{}, err
	}

	err = errors.ParseError(resp.StatusCode)
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
