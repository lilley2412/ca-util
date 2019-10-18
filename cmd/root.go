package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kris-nova/logger"
	"github.com/lilley2412/ca-util/internal/tls"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

type CaUtilConfig struct {
	CertAuthorities []*tls.Cert
}

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ca-util",
	Short: "cert authority and tls utility",
	Long:  `Create self-signed ca's, created and sign certs, optionally create k8s secrets.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ca-util.yaml)")
	rootCmd.PersistentFlags().IntVarP(&logger.Level, "log", "l", 4, "set log level, use 0 to silence, 4 for debugging")
	colorValue := rootCmd.PersistentFlags().StringP("color", "C", "true", "toggle colorized logs (valid options: true, false, fabulous)")

	cobra.OnInitialize(func() {
		// Control colored output
		logger.Color = *colorValue == "true"
		logger.Fabulous = *colorValue == "fabulous"
		// Add timestamps for debugging
		logger.Timestamps = logger.Level >= 4
	})

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)

		if err := viper.ReadInConfig(); err != nil {
			logger.Critical("Config file not found: %s", cfgFile)
			os.Exit(-1)
		}

		// viper.SetEnvPrefix("CAUTIL")
		// viper.AutomaticEnv()

		err := viper.Unmarshal(&config)
		if err != nil {
			logger.Critical("error reading config: %s", err.Error())
			os.Exit(-1)
		}

		// logger.Debug("parsed config: %s", prettyPrint(config))

	}
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
