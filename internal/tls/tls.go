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
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/kris-nova/logger"
)

type Cert struct {
	Organization       string
	CommonName         string
	ValidSinceDuration string
	NotBefore          time.Time
	ValidForDuration   string
	NotAfter           time.Time
	DNSNames           []string
	SignedCerts        []*Cert
	IsCa               bool
	K8sSecretName      string
}

type CertKeyPair struct {
	CertPem string
	CertKey string
}

type RootCaPair struct {
	CertPem string
	CertKey string
}

func (c *Cert) Generate() (*CertKeyPair, error) {
	pair := &CertKeyPair{}
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

	pair.CertKey, err = getPemString(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return nil, err
	}

	root509Def := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{c.Organization},
			CommonName:   c.CommonName,
		},
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		KeyUsage:              keyUsage(c.IsCa),
		ExtKeyUsage:           extKeyUsage(c.IsCa),
		BasicConstraintsValid: true,
		IsCA:                  c.IsCa,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &root509Def, &root509Def, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	pair.CertPem, err = getPemString(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return nil, err
	}

	return pair, nil
}

func keyUsage(isCa bool) x509.KeyUsage {
	if isCa {
		return x509.KeyUsageCertSign
	} else {
		return x509.KeyUsageEncipherOnly
	}
}

func extKeyUsage(isCa bool) []x509.ExtKeyUsage {
	if isCa {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

// GetOrCreateRootCa gets or creates a root CA tls secret in the kube-system namespace
// func GetOrCreateRootCa() (*RootCaPair, error) {
// 	// TODO - check for secret first
// 	newCa, err := createRootCa()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return newCa, nil
// }

// func getRootCaSecret() *v1.Secret {
// 	// TODO
// 	return nil
// }

// func createRootCa() (*RootCaPair, error) {
// 	ca := &RootCaPair{}
// 	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
// 	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
// 	if err != nil {
// 		return nil, err
// 	}

// 	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		return nil, err
// 	}

// 	keyBytes, err := x509.MarshalECPrivateKey(rootKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ca.CertKey, err = getPemString(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
// 	if err != nil {
// 		return nil, err
// 	}

// 	// TODO - make these configurable
// 	notBefore := time.Now()
// 	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

// 	root509Def := x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject: pkix.Name{
// 			Organization: []string{"k8s cluster"},
// 			CommonName:   "Root CA",
// 		},
// 		NotBefore:             notBefore,
// 		NotAfter:              notAfter,
// 		KeyUsage:              x509.KeyUsageCertSign,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 		IsCA:                  true,
// 	}

// 	certBytes, err := x509.CreateCertificate(rand.Reader, &root509Def, &root509Def, &rootKey.PublicKey, rootKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ca.CertPem, err = getPemString(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
// 	if err != nil {
// 		return nil, err
// 	}

// 	return ca, nil
// }

func getPemString(p *pem.Block) (string, error) {
	var buff bytes.Buffer
	pemWriter := bufio.NewWriter(&buff)
	if err := pem.Encode(pemWriter, p); err != nil {
		return "", err
	}
	pemWriter.Flush()
	return buff.String(), nil
}

func (c *Cert) SetDefaults() []string {
	var errors []string

	// common name is the only required field
	if c.CommonName == "" {
		errors = append(errors, fmt.Sprintf("commonName is required for cert: %+v", c))
	}

	logger.Debug("Validating config for '%s'", c.CommonName)

	if c.Organization == "" {
		c.Organization = "My Org"
	}

	// if not set, the cert notBefore will be now - 24h
	if c.ValidSinceDuration == "" {
		c.ValidSinceDuration = "24h"
	}

	if d, err := time.ParseDuration(c.ValidSinceDuration); err != nil {
		errors = append(errors, fmt.Sprintf("failed to pasrse ValidSinceDuration (%s) for cert: %+v, error: %s", c.ValidSinceDuration, c, err.Error()))
	} else {
		c.NotBefore = time.Now().AddDate(0, 0, int(-d.Hours()/24))
	}

	// if not set, the cert notAfter will be now + 10 years
	if c.ValidForDuration == "" {
		c.ValidForDuration = "87600h"
	}
	if d, err := time.ParseDuration(c.ValidForDuration); err != nil {
		errors = append(errors, fmt.Sprintf("failed to pasrse ValidForDuration (%s) for cert: %+v, error: %s", c.ValidForDuration, c, err.Error()))
	} else {
		c.NotAfter = time.Now().AddDate(0, 0, int(d.Hours()/24))
	}

	c.K8sSecretName = fmt.Sprintf("%s-tls", strings.ReplaceAll(c.CommonName, " ", ""))

	return errors
}
