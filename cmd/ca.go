package cmd

import (
	"os"

	"github.com/kris-nova/logger"
	"github.com/lilley2412/ca-util/internal/creator"
	"github.com/lilley2412/ca-util/internal/tls"
	"github.com/spf13/cobra"
)

// caCmd represents the ca command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "create a self-signed root ca",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(config.CertAuthorities) > 0 {
			logger.Critical("--config should not be used with 'create ca', to create a bundle with a config file, use 'ca-util create --config myfile.yaml'")
			os.Exit(0)
		}
		cn, _ := cmd.Flags().GetString("common-name")
		createSecret, _ := cmd.Flags().GetBool("k8s")
		ns, _ := cmd.Flags().GetString("namespace")

		ca := &tls.Cert{
			CommonName: cn,
			IsCa:       true,
		}
		ca.SetDefaults()
		_, err := creator.CreateCerts(&creator.Opts{CreateK8sSecret: createSecret, Certs: []*tls.Cert{ca}, Namespace: ns})
		if err != nil {
			logger.Critical("error creating certs, %s", err.Error())
			os.Exit(-1)
		}
	},
}

func init() {
	createCmd.AddCommand(caCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	caCmd.PersistentFlags().BoolP("k8s", "k", false, "if set, create the secrets in kubernetes")
	caCmd.PersistentFlags().StringP("namespace", "n", "default", "namespace to create secrets in, only used if --k8s / -k is set, defaults to 'Default'")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	caCmd.Flags().StringP("common-name", "c", "", "Common name of the CA to create")
	caCmd.MarkFlagRequired("common-name")
}
