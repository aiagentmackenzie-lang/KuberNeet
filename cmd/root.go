package cmd

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version string
	Commit  string
	Date    string

	cfgFile string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "kuberneet",
	Short: "Kubernetes security scanner with educational DNA",
	Long: color.CyanString(`
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗████████╗
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝
█████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  █████╗     ██║   
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██╔══╝     ██║   
██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████╗   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   

`) + `A Kubernetes security scanner that explains WHY something is insecure,
maps findings to attack paths, and generates exact remediation YAML.`,
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kuberneet/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.kuberneet")
			viper.SetConfigName("config")
			viper.SetConfigType("yaml")
			os.MkdirAll(home+"/.kuberneet", 0755)
		}
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("KUBERNEET")

	if err := viper.ReadInConfig(); err == nil && verbose {
		color.Blue("Using config file: %s", viper.ConfigFileUsed())
	}
}
