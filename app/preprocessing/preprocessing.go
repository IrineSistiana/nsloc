package track

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/IrineSistiana/nsloc/app"
	"github.com/IrineSistiana/nsloc/pkg/mlog"
	"github.com/IrineSistiana/nsloc/pkg/utils"

	"github.com/spf13/cobra"
	ps "github.com/weppos/publicsuffix-go/publicsuffix"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

func init() {
	app.RootCmd.AddCommand(newTrackCmd())
}

var (
	logger = mlog.L()
)

func newTrackCmd() *cobra.Command {
	var (
		pslFp string
		outFp string
	)
	c := &cobra.Command{
		Use:                   "preprocessing --psl psl.txt [--out psn.txt] raw_domain_list.txt ...",
		Short:                 "Preprocessing raw domains to ascii public suffix domains.",
		DisableFlagsInUseLine: false,
		Args:                  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			run(pslFp, outFp, args)
		},
	}
	c.Flags().StringVar(&pslFp, "psl", "", "use public suffix list to automatically trim domains to the registered level, see: https://publicsuffix.org/list/")
	c.Flags().StringVarP(&outFp, "out", "o", "psn.txt", "output file")
	c.MarkFlagRequired("psl")
	return c
}

func run(pslFp, outFp string, fps []string) {
	psl, err := ps.NewListFromFile(pslFp, &ps.ParserOption{PrivateDomains: false})
	if err != nil {
		logger.Fatal("failed to load public suffix list", zap.Error(err))
	}
	logger.Info("public suffix list loaded", zap.Int("len", psl.Size()))

	m := make(map[string]struct{})
	for _, fp := range fps {
		logger.Info("processing domain list", zap.String("file", fp))
		_, err := loadPsnFromFileToMap(fp, psl, m)
		if err != nil {
			logger.Fatal("failed to process domain list", zap.String("file", fp), zap.Error(err))
		}
	}
	logger.Info("domain lists loaded", zap.Int("total_psn", len(m)))
	logger.Info("writing to file", zap.String("file", outFp))

	out, err := os.Create(outFp)
	if err != nil {
		logger.Fatal("failed to open output file", zap.Error(err))
	}
	defer out.Close()

	ms := make([]string, 0, len(m))
	for fqdn := range m {
		ms = append(ms, utils.TrimDot(fqdn))
	}
	slices.Sort(ms)

	b := new(bytes.Buffer)
	for _, s := range ms {
		b.WriteString(s)
		b.WriteRune('\n')
	}
	_, err = out.Write(b.Bytes())
	if err != nil {
		logger.Fatal("failed to write output file", zap.Error(err))
	}
}

func loadPsnFromFileToMap(fp string, psl *ps.List, m map[string]struct{}) (int, error) {
	f, err := os.Open(fp)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	domainC := 0
	lineC := 0
	for s.Scan() {
		lineC++
		fqdn := utils.HandleDomainListLine(s.Text())
		if len(fqdn) == 0 {
			continue
		}

		psn := pslTrim(psl, fqdn)
		if len(psn) == 0 {
			logger.Debug("psl matched failed", zap.String("fqdn", fqdn))
			continue
		}
		m[psn] = struct{}{}
		domainC++
	}
	return domainC, nil
}

func cutLv(fqdn string, lv int) string {
	if lv <= 0 {
		return fqdn
	}

	clv := 0
	for i := len(fqdn) - 1; i >= 0; i-- {
		if fqdn[i] == '.' {
			clv++
		}
		if clv > lv {
			return fqdn[i+1:]
		}
	}
	return fqdn
}

var (
	pslFindOpt = &ps.FindOptions{
		IgnorePrivate: false,
		DefaultRule:   nil,
	}
)

func pslTrim(l *ps.List, fqdn string) string {
	n := strings.TrimSuffix(fqdn, ".")
	r := l.Find(n, pslFindOpt)
	if r == nil { // no suffix matched, possible invalid domain name.
		return ""
	}

	ruleLv := 0
	if len(r.Value) > 0 {
		ruleLv = strings.Count(r.Value, ".") + 1
	}
	return cutLv(fqdn, ruleLv+1)
}
