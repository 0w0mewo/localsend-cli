package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/0w0mewo/localsend-cli/templates"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

var aliasAdj = []string{
	"Adorable",
	"Beautiful",
	"Big",
	"Bright",
	"Clean",
	"Clever",
	"Cool",
	"Cute",
	"Cunning",
	"Determined",
	"Energetic",
	"Efficient",
	"Fantastic",
	"Fast",
	"Fine",
	"Fresh",
	"Good",
	"Gorgeous",
	"Great",
	"Handsome",
	"Hot",
	"Kind",
	"Lovely",
	"Mystic",
	"Neat",
	"Nice",
	"Patient",
	"Pretty",
	"Powerful",
	"Rich",
	"Secret",
	"Smart",
	"Solid",
	"Special",
	"Strategic",
	"Strong",
	"Tidy",
	"Wise",
}

var aliasFruit = []string{
	"Apple",
	"Avocado",
	"Banana",
	"Blackberry",
	"Blueberry",
	"Broccoli",
	"Carrot",
	"Cherry",
	"Coconut",
	"Grape",
	"Lemon",
	"Lettuce",
	"Mango",
	"Melon",
	"Mushroom",
	"Onion",
	"Orange",
	"Papaya",
	"Peach",
	"Pear",
	"Pineapple",
	"Potato",
	"Pumpkin",
	"Raspberry",
	"Strawberry",
	"Tomato",
}

func GenAndSaveTLScert(privKeyFile, certFile string) (tls.Certificate, error) {
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

	// save certificate
	err = os.WriteFile(certFile, certPem, 0o640)
	if err != nil {
		return tls.Certificate{}, err
	}

	// save private key
	err = os.WriteFile(privKeyFile, certPrivKeyPem, 0o640)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPem, certPrivKeyPem)
}

func LoadOrGenTLScert(privKeyFile, certFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, privKeyFile)
	if err == nil {
		return cert, err
	}

	return GenAndSaveTLScert(privKeyFile, certFile)
}

func GenAlias() string {
	adj := utils.RandChoice(aliasAdj)
	fruit := utils.RandChoice(aliasFruit)

	return adj + " " + fruit
}

func NewWebServer(withTemplateEngine ...bool) *fiber.App {
	config := fiber.Config{
		Prefork:               false,
		DisableStartupMessage: true,
	//	BodyLimit:             100 * 1024 * 1024 * 1024, // 100G
		BodyLimit:             1 * 1024 * 1024 * 1024, // 1G (for 32-bit)
	}

	if len(withTemplateEngine) > 0 {
		if withTemplateEngine[0] {
			config.Views = html.NewFileSystem(http.FS(templates.TemplatesFS), ".html")
		}
	}

	return fiber.New(config)
}
