/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"lilley2412/root-ca-creator/internal/common"
	"lilley2412/root-ca-creator/internal/tls"
	"os"

	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// secretCmd represents the secret command
var secretCmd = &cobra.Command{
	Use:   "secret [name] <flags>",
	Args:  cobra.ExactArgs(1),
	Short: "Creates a root CA as a k8s TLS secret.",
	Long: `example:
	
	Creates a root CA as TLS secret my-tls-secret with default values in the "default" k8s namespace:

	root-ca-creator secret my-tls-secret`,
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		ns, _ := cmd.Flags().GetString("namespace")

		k, err := common.CreateK8sClientset()
		if err != nil {
			logger.Critical("failed to create k8s client: %s", err.Error())
			os.Exit(-1)
		}

		logger.Debug("checking if secret '%s' exists in namespace '%s'", name, ns)

		secrets, err := k.CoreV1().Secrets(ns).List(metav1.ListOptions{
			FieldSelector: fmt.Sprintf("metadata.name=%s", name),
		})

		if err != nil {
			logger.Critical("could not get secrets, %s", err.Error())
			os.Exit(-1)
		}

		// can only be 1 due to filter used
		if len(secrets.Items) > 0 {
			logger.Info("secret %s already exists in namespace %s", name, ns)
			os.Exit(0)
		}

		// generate a new root ca cert
		cert, err := tls.GetOrCreateRootCa()

		if err != nil {
			logger.Critical("failed to generate tls cert: %s", err.Error())
			os.Exit(-1)
		}

		// create the secret
		if _, err := k.CoreV1().Secrets(ns).Create(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    map[string]string{"createdBy": "root-ca-creator"},
			},
			Type: "tls",
			StringData: map[string]string{
				"ca.crt":  cert.CertPem,
				"tls.crt": cert.CertPem,
				"tls.key": cert.CertKey,
			},
		}); err != nil {
			logger.Critical("failed to create k8s secret: %s", err.Error())
			os.Exit(-1)
		}

		logger.Info("secret %s created in ns %s", name, ns)
	},
}

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.Flags().StringP("namespace", "n", "default", "namespace secret will be created in")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// secretCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// secretCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
