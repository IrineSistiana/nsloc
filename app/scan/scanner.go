package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"

	dnsClient "github.com/IrineSistiana/nsloc/pkg/dns_client"
	"github.com/IrineSistiana/nsloc/pkg/utils"
	"github.com/miekg/dns"
	geoip2 "github.com/oschwald/geoip2-golang"
	"github.com/schollz/progressbar/v3"
	"go.uber.org/zap"
)

func runScan(ctx context.Context, a args) error {
	var upstreamAddrs []netip.AddrPort
	for _, s := range a.upstream {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("invalid upstream, %w", err)
		}
		upstreamAddrs = append(upstreamAddrs, ap)
	}
	if len(upstreamAddrs) == 0 {
		return errors.New("no upstream address")
	}

	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("failed to open socket, %w", err)
	}
	dc := dnsClient.New(uc)
	defer dc.Close()

	geoReader, err := geoip2.Open(a.geoipFp)
	if err != nil {
		return fmt.Errorf("failed to open geoip file, %w", err)
	}

	inputF, err := os.Open(a.inputFp)
	if err != nil {
		return fmt.Errorf("failed to open input file, %w", err)
	}
	defer inputF.Close()

	domains := make(map[string]struct{})
	err = utils.ReadDomainListFromReader(inputF, func(asciiFqdn string) error {
		domains[asciiFqdn] = struct{}{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to read input file, %w", err)
	}

	out, err := os.Create(a.outFp)
	if err != nil {
		return fmt.Errorf("failed to create output file, %w", err)
	}
	defer out.Close()

	scanner := &scanner{
		dnsClient:     dc,
		geoReader:     geoReader,
		upstreamAddrs: upstreamAddrs,
	}

	bar := progressbar.NewOptions(len(domains),
		progressbar.OptionThrottle(time.Second),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("dm"),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("Scanning..."),
		progressbar.OptionShowDescriptionAtLineEnd(),
		progressbar.OptionClearOnFinish(),
	)

	grLimiter := newGrPool(a.concurrent)
	rl := rate.NewLimiter(rate.Limit(a.sps), a.sps)
	wg := new(sync.WaitGroup)
	resChan := make(chan *Result)
	doneChan := make(chan struct{})
	go func() {
		for d := range domains {
			d := d
			select {
			case <-ctx.Done():
				return
			case grLimiter.acquire() <- struct{}{}:
				wg.Add(1)
				go func() {
					defer grLimiter.release()
					defer wg.Done()

					err := rl.Wait(ctx)
					if err != nil {
						return
					}

					select {
					case resChan <- scanner.scan(ctx, d):
					case <-ctx.Done():
					}
				}()
			}
		}
		go func() {
			wg.Wait()
			close(doneChan)
		}()
	}()

	bb := new(bytes.Buffer)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneChan:
			bar.Finish()
			return nil
		case res := <-resChan:
			bar.Describe(fmt.Sprintf("Scanning...[%s][t: %dms]", res.Fqdn, res.ElapsedMs))
			bar.Add(1)

			encoder := json.NewEncoder(bb)
			if err := encoder.Encode(res); err != nil {
				return fmt.Errorf("failed to encode result, %w", err)
			}
			if _, err := out.Write(bb.Bytes()); err != nil {
				return fmt.Errorf("failed to write output, %w", err)
			}
			bb.Reset()
		}
	}
}

type Result struct {
	Fqdn      string   `json:"fqdn,omitempty"`
	ElapsedMs int64    `json:"elapsed_ms,omitempty"`
	Nss       []string `json:"nss,omitempty"`
	NsAddrs   []string `json:"ns_addrs,omitempty"`
	LocCodes  []string `json:"locs,omitempty"`
	Errs      []string `json:"errs,omitempty"`
}

type scanner struct {
	dnsClient     *dnsClient.Client
	geoReader     *geoip2.Reader
	upstreamAddrs []netip.AddrPort
}

func (s *scanner) scan(ctx context.Context, fqdn string) (r *Result) {
	r = new(Result)
	r.Fqdn = fqdn

	start := time.Now()
	defer func() {
		r.ElapsedMs = time.Since(start).Milliseconds()
	}()

	nss, err := s.queryNs(ctx, fqdn)
	if err != nil {
		r.Errs = append(r.Errs, fmt.Sprintf("failed to lookup ns, %s", err))
		return
	}
	if len(nss) == 0 {
		r.Errs = append(r.Errs, "no ns record")
		return
	}
	r.Nss = nss

	errL := new(sync.Mutex)
	errs := make([]error, 0)
	addrsL := new(sync.Mutex)
	addrsM := make(map[netip.Addr]struct{})

	appendErr := func(err error) {
		errL.Lock()
		defer errL.Unlock()
		errs = append(errs, err)
	}
	appendNsAddr := func(s []netip.Addr) {
		addrsL.Lock()
		defer addrsL.Unlock()
		for _, a := range s {
			addrsM[a] = struct{}{}
		}
	}

	wg := new(sync.WaitGroup)
	for i, ns := range nss {
		if i > 3 { // Lookup at most 3 name servers. Should be enough.
			break
		}
		ns := ns
		for _, qt := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
			qt := qt
			wg.Add(1)
			go func() {
				defer wg.Done()

				nsAddrs, err := s.queryAddr(ctx, ns, qt)
				if err != nil {
					appendErr(fmt.Errorf("failed to lookup ns %s addr qt=%d, %w", ns, qt, err))
				}
				if len(nsAddrs) > 0 {
					appendNsAddr(nsAddrs)
				}
			}()
		}
	}
	wg.Wait()

	locCodesM := make(map[string]struct{})
	for addr := range addrsM {
		r.NsAddrs = append(r.NsAddrs, addr.String())

		c, err := s.geoReader.Country(addr.AsSlice())
		if err != nil {
			logger.Error("geoip database read err", zap.Error(err)) // Fatal error maybe?
			continue
		}
		if s := c.Country.IsoCode; len(s) > 0 {
			locCodesM[s] = struct{}{}
		}
	}
	r.LocCodes = key(locCodesM)

	for _, err := range errs {
		r.Errs = append(r.Errs, err.Error())
	}

	// Just make result looks better.
	slices.Sort(r.Nss)
	slices.Sort(r.NsAddrs)
	slices.Sort(r.LocCodes)
	slices.Sort(r.Errs)
	return
}

type grPool struct {
	c chan struct{}
}

func newGrPool(size int) *grPool {
	return &grPool{c: make(chan struct{}, size)}
}

func (p *grPool) acquire() chan<- struct{} {
	return p.c
}

func (p *grPool) release() {
	select {
	case <-p.c:
	default:
		panic("invalid release call")
	}
}

func (s *scanner) query(ctx context.Context, fqdn string, qt uint16) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(fqdn, qt)
	q.SetEdns0(1200, false)
	q.Id = s.dnsClient.NextQid()
	return s.dnsClient.Query(ctx, q, s.upstreamAddrs[rand.Intn(len(s.upstreamAddrs))])
}

func (s *scanner) queryNs(ctx context.Context, fqdn string) ([]string, error) {
	resp, err := s.query(ctx, fqdn, dns.TypeNS)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("bad rcode %d", resp.Rcode)
	}

	// find ns records
	var nss []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nss = append(nss, ns.Ns)
		}
	}
	return nss, nil
}

func (s *scanner) queryAddr(ctx context.Context, fqdn string, qt uint16) ([]netip.Addr, error) {
	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return nil, fmt.Errorf("invalid query type %d", qt)
	}

	resp, err := s.query(ctx, fqdn, qt)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("bad rcode %d", resp.Rcode)
	}

	var addrs []netip.Addr
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		a, ok := netip.AddrFromSlice(ip)
		if ok {
			addrs = append(addrs, a)
		}
	}
	return addrs, nil
}

func key[K comparable, V any](m map[K]V) []K {
	if len(m) == 0 {
		return nil
	}
	s := make([]K, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}
