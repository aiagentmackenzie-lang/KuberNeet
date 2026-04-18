package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(color.CyanString("KuberNeet v%s\n"), Version)
		fmt.Printf("  Commit: %s\n", Commit)
		fmt.Printf("  Built:  %s\n", Date)
		fmt.Printf("  Go:     %s\n", "1.24")
		fmt.Printf("  Client-go: v0.28.4\n")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
