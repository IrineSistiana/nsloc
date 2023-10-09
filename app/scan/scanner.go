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

	"golang.org/x/time/rate"

	dnsClient "github.com/IrineSistiana/nsloc/pkg/dns_client"
	"github.com/IrineSistiana/nsloc/pkg/utils"
	"github.com/miekg/dns"
	geoip2 "github.com/oschwald/geoip2-golang"
	"github.com/schollz/progressbar/v3"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
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
	Ns        string   `json:"ns,omitempty"`
	LocCode   []string `json:"loc,omitempty"`
	ElapsedMs int64    `json:"elapsed_ms,omitempty"`

	m      sync.Mutex
	NsAddr []string `json:"ns_addr,omitempty"`
	Errs   []string `json:"errs,omitempty"`
}

func (r *Result) appendNsAddr(ip []netip.Addr) {
	r.m.Lock()
	defer r.m.Unlock()
	addrsStr := ip2str(ip)
	slices.Sort(addrsStr)
	r.NsAddr = append(r.NsAddr, addrsStr...)
}

func (r *Result) appendErr(err error) {
	r.m.Lock()
	defer r.m.Unlock()
	r.Errs = append(r.Errs, err.Error())
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

	ns, err := s.queryMainNs(ctx, fqdn)
	if err != nil {
		r.Errs = append(r.Errs, fmt.Sprintf("failed to lookup main ns, %s", err))
		return
	}
	if len(ns) == 0 {
		r.Errs = append(r.Errs, "no soa record")
		return
	}
	r.Ns = ns

	geoCcM := new(sync.Mutex)
	geoCc := make(map[string]struct{})
	wg := new(sync.WaitGroup)

	for _, qt := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
		qt := qt
		wg.Add(1)
		go func() {
			defer wg.Done()

			nsAddrs, err := s.queryAddr(ctx, ns, qt)
			if err != nil {
				r.appendErr(fmt.Errorf("failed to lookup ns addr qt=%d, %w", qt, err))
			}
			if len(nsAddrs) > 0 {
				r.appendNsAddr(nsAddrs)
				for _, ip := range nsAddrs {
					c, err := s.geoReader.Country(ip.AsSlice())
					if err != nil {
						logger.Error("geoip database read err", zap.Error(err))
						continue
					}
					if s := c.Country.IsoCode; len(s) > 0 {
						geoCcM.Lock()
						geoCc[s] = struct{}{}
						geoCcM.Unlock()
					}
				}
			}
		}()
	}
	wg.Wait()

	for cc := range geoCc {
		r.LocCode = append(r.LocCode, cc)
		slices.Sort(r.LocCode)
	}
	return
}

func ip2str(ips []netip.Addr) []string {
	var r []string
	for _, ip := range ips {
		r = append(r, ip.String())
	}
	return r
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

func (s *scanner) queryMainNs(ctx context.Context, fqdn string) (string, error) {
	resp, err := s.query(ctx, fqdn, dns.TypeSOA)
	if err != nil {
		return "", err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("bad rcode %d", resp.Rcode)
	}

	// find soa
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Ns, nil
		}
	}
	return "", nil
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
