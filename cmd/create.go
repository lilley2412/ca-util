package cmd

import (
	"fmt"
	"os"

	"github.com/kris-nova/logger"
	"github.com/lilley2412/ca-util/internal/creator"
	"github.com/spf13/cobra"
)

var config CaUtilConfig

// createCaCmd represents the createCa command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "create cert(s)",
	Long: `Create a root ca, self-signed cert, or generate a collection of certs.
	
Example: generate a root CA with default values:

	ca-util create ca -c "my common name"

Example: generate a bundle of certs using a config file:

	ca-util create --config "myfile.yaml"
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(config.CertAuthorities) == 0 {
			fmt.Println("must specify a sub-command or provide a config file with --config")
			cmd.Help()
			os.Exit(0)
		}

		if errors := parseConfig(&config); len(errors) > 0 {
			logger.Critical("config validation failed:")
			for _, e := range errors {
				logger.Critical(e)
			}
			os.Exit(-1)
		}

		creator.CreateCerts(&creator.Opts{CreateK8sSecret: false, Certs: config.CertAuthorities})

	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCaCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func parseConfig(c *CaUtilConfig) []string {
	var errors []string

	for _, ca := range c.CertAuthorities {
		ca.IsCa = true
		if e := ca.SetDefaults(); len(e) > 0 {
			errors = append(errors, e...)
		}

		for _, sc := range ca.SignedCerts {
			sc.IsCa = false
			if e := sc.SetDefaults(); len(e) > 0 {
				errors = append(errors, e...)
			}
		}
	}

	return errors
}
