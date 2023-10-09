package scan

import (
	"github.com/IrineSistiana/nsloc/app"
	"github.com/IrineSistiana/nsloc/pkg/mlog"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	scanCmd := newScanCmd()
	app.RootCmd.AddCommand(scanCmd)
}

var (
	logger = mlog.L()
)

type args struct {
	concurrent int
	sps        int
	upstream   []string
	geoipFp    string
	inputFp    string
	outFp      string
}

func newScanCmd() *cobra.Command {
	var a args
	c := &cobra.Command{
		Use:                   "scan",
		Short:                 "Scan ns info",
		DisableFlagsInUseLine: false,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			ctx := cmd.Context()
			err := runScan(ctx, a)
			if err != nil {
				logger.Fatal("scanner exited", zap.Error(err))
			}
		},
	}
	c.PersistentFlags().IntVar(&a.concurrent, "cc", 20, "maximum number of concurrent queries")
	c.PersistentFlags().IntVar(&a.sps, "sps", 100, "maximum number of scan domains pre sec")
	c.PersistentFlags().StringArrayVarP(&a.upstream, "upstream", "u", []string{"8.8.8.8:53"}, "dns upstream server that can solve domain's addresses")
	c.PersistentFlags().StringVarP(&a.inputFp, "input", "i", "", "input domain files")
	c.PersistentFlags().StringVarP(&a.geoipFp, "geoip", "g", "", "mmdb file with country data")
	c.PersistentFlags().StringVarP(&a.outFp, "out", "o", "out.jsonl", "output file")
	c.MarkFlagRequired("input")
	c.MarkFlagRequired("geoip")
	return c
}
