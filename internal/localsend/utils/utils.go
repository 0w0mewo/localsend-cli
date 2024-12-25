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
	"time"

	"github.com/0w0mewo/localsend-cli/internal/utils"
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

var HttpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func GenTLScert() (tls.Certificate, error) {
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

func GenAlias() string {
	adj := utils.RandChoice(aliasAdj)
	fruit := utils.RandChoice(aliasFruit)

	return adj + " " + fruit
}
