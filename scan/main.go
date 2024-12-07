package main

import (
	"os"

	"github.com/refoo0/sca/scan/commands"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "sca tools results analysis",
	Long:  `scanner is a tool to analyze the results of sca tools`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cmd := commands.NewAnalysisCommand()
	rootCmd.AddCommand(cmd)
}

func main() {
	Execute()
}
