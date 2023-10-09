package utils

import (
	"bufio"
	"io"
	"strings"

	"github.com/IrineSistiana/nsloc/pkg/mlog"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

var logger = mlog.L()

// Remove comment after "#".
// Trim space.
// CanonicalDomainName.
func HandleDomainListLine(sl string) string {
	sl, _, _ = strings.Cut(sl, "#") // remove comments
	sl = strings.TrimSpace(sl)
	if len(sl) == 0 { // empty line
		return ""
	}

	d, err := CanonicalDomainName(sl)
	if err != nil {
		logger.Debug("invalid domain", zap.String("fqdn", sl), zap.Error(err))
		return "" // ignore invalid domains
	}
	return d
}

type DomainPreprocessingFunc func(asciiFqdn string) error

func ReadDomainListFromReader(r io.Reader, pf DomainPreprocessingFunc) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		asciiFqdn := HandleDomainListLine(s.Text())
		if len(asciiFqdn) > 0 {
			if err := pf(asciiFqdn); err != nil {
				return err
			}
		}
	}
	return s.Err()
}

func CanonicalDomainName(s string) (string, error) {
	s = strings.ToLower(s)
	s, err := idna.Punycode.ToASCII(s)
	if err != nil {
		return "", err
	}
	return Fqdn(s), nil
}

func Fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func TrimDot(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
