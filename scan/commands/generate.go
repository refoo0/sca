package commands

import (
	"github.com/refoo0/sca/scan/utils"
	"github.com/spf13/cobra"
)

func NewGenerateCommand() *cobra.Command {
	analysisCmd := &cobra.Command{
		Use:   "generate",
		Short: "",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			//args[0] = path
			//args[1] = output

			utils.Generate(args[0], args[1])

		},
	}

	return analysisCmd
}
