package common

import (
	"github.com/kris-nova/logger"
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CreateClientset creates a k8s clientset
func CreateK8sClientset() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err != nil {
		logger.Info("InClusterConfig failed, trying out-of-cluster configuration")
		logger.Debug("InClusterConfig failed with %s", err.Error())
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		config, err = kubeconfig.ClientConfig()
		if err != nil {
			return nil, err
		}
		logger.Info("out-of-cluster configuration being used")
	} else {
		logger.Info("InClusterConfig being used")
	}

	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	return clientset, nil
}
