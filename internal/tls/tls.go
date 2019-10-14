package tls

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type ClusterCa struct {
	CertPem string
	CertKey string
}

// GetOrCreateRootCa gets or creates a root CA tls secret in the kube-system namespace
func GetOrCreateRootCa() (*ClusterCa, error) {
	// TODO - check for secret first
	newCa, err := createRootCa()
	if err != nil {
		return nil, err
	}
	return newCa, nil
}

// func getRootCaSecret() *v1.Secret {
// 	// TODO
// 	return nil
// }

func createRootCa() (*ClusterCa, error) {
	ca := &ClusterCa{}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, err
	}

	ca.CertKey, err = getPemString(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return nil, err
	}

	// TODO - make these configurable
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	root509Def := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"k8s cluster"},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &root509Def, &root509Def, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	ca.CertPem, err = getPemString(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return nil, err
	}

	return ca, nil
}

func getPemString(p *pem.Block) (string, error) {
	var buff bytes.Buffer
	pemWriter := bufio.NewWriter(&buff)
	if err := pem.Encode(pemWriter, p); err != nil {
		return "", err
	}
	pemWriter.Flush()
	return buff.String(), nil
}
