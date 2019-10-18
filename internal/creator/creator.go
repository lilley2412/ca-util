package creator

import (
	"fmt"
	"os"

	"github.com/kris-nova/logger"
	"github.com/lilley2412/ca-util/internal/common"
	"github.com/lilley2412/ca-util/internal/tls"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
)

type Opts struct {
	CreateK8sSecret bool
	Certs           []*tls.Cert
	Namespace       string
}

var k *kubernetes.Clientset

func CreateCerts(opts *Opts) ([]*tls.CertKeyPair, error) {
	// pure file-gen logic
	if !opts.CreateK8sSecret {
		return createCerts(opts.Certs...)
	}

	// k8s logic
	var err error
	k, err = common.CreateK8sClientset()
	if err != nil {
		logger.Critical("failed to create k8s client: %s", err.Error())
		os.Exit(-1)
	}

	_, certsWithoutSecrets := getExistingSecrets(opts.Namespace, opts.Certs...)

	return createSecrets(opts.Namespace, certsWithoutSecrets...)
}

func createSecrets(ns string, certs ...*tls.Cert) ([]*tls.CertKeyPair, error) {
	var pems []*tls.CertKeyPair

	for _, c := range certs {
		p, err := createCerts(c)
		if err != nil {
			logger.Critical("error creating cert, %s", err.Error())
			return nil, err
		}

		pems = append(pems, p[0])

		// create the secret
		if _, err := k.CoreV1().Secrets(ns).Create(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.K8sSecretName,
				Namespace: ns,
				Labels:    map[string]string{"createdBy": "ca-util"},
			},
			Type: "tls",
			StringData: map[string]string{
				"ca.crt":  p[0].CertPem,
				"tls.crt": p[0].CertPem,
				"tls.key": p[0].CertKey,
			},
		}); err != nil {
			logger.Critical("failed to create k8s secret: %s", err.Error())
			return nil, err
		}
		logger.Info("secret '%s' created in namespace '%s'", c.K8sSecretName, ns)
	}

	return pems, nil
}

func getExistingSecrets(ns string, certs ...*tls.Cert) ([]*v1.Secret, []*tls.Cert) {
	var sx []*v1.Secret
	var cx []*tls.Cert

	for _, c := range certs {
		logger.Debug("checking if secret '%s' exists in namespace '%s'", c.K8sSecretName, ns)

		secrets, err := k.CoreV1().Secrets(ns).List(metav1.ListOptions{
			FieldSelector: fmt.Sprintf("metadata.name=%s", c.K8sSecretName),
		})

		if err != nil {
			logger.Critical("could not get secrets, %s", err.Error())
			os.Exit(-1)
		}

		// can only be 1 due to filter used
		if len(secrets.Items) > 0 {
			sx = append(sx, &secrets.Items[0])
			logger.Debug("secret '%s' already exists in namespace '%s'", c.K8sSecretName, ns)
		} else {
			logger.Debug("secret '%s' does not exists in namespace '%s' and will be created", c.K8sSecretName, ns)
			cx = append(cx, c)
		}
	}
	return sx, cx
}

func createCerts(certs ...*tls.Cert) ([]*tls.CertKeyPair, error) {
	var pems []*tls.CertKeyPair

	for _, c := range certs {
		pair, err := c.Generate()
		if err != nil {
			logger.Critical("error generaing cert: %s", err.Error())
			return nil, err
		}

		pems = append(pems, pair)

		// if this is a CA and has child certs to be created ...
		if c.IsCa && len(c.SignedCerts) > 0 {
			for _, sc := range c.SignedCerts {
				pair, err := sc.Generate()
				if err != nil {
					logger.Critical("error generaing signed cert from CA: %s", err.Error())
					return nil, err
				}
				pems = append(pems, pair)
			}
		}
	}
	return pems, nil
}
