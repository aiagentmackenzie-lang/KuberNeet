package cmd

import (
	"fmt"
	"runtime"

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
		fmt.Printf("  Go:     %s\n", runtime.Version())
		fmt.Printf("  Client-go: v0.34.1\n")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
