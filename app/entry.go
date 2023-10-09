package app

import (
	"github.com/IrineSistiana/nsloc/pkg/mlog"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
)

var RootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	var args struct {
		debug bool
	}
	c := &cobra.Command{
		Use:                   "nsloc",
		DisableFlagsInUseLine: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if args.debug {
				mlog.SetLevel(zapcore.DebugLevel)
			}
		},
	}

	c.PersistentFlags().BoolVar(&args.debug, "debug", false, "print debug log")
	return c
}
