package commands

import (
	"github.com/refoo0/sca/scan/parse"

	"github.com/spf13/cobra"
)

func NewAnalysisCommand() *cobra.Command {
	analysisCmd := &cobra.Command{
		Use:   "analysis",
		Short: "analysis the results of sca tools",
		Args:  cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {

			//args[0] = osvPath
			//args[1] = trivyPath
			//args[2] = snykPath
			//args[3] = target
			parse.Parse(args[0], args[1], args[2], args[3])

		},
	}

	return analysisCmd
}
