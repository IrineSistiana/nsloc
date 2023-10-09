package dnsClient

import (
	"sync"

	"github.com/miekg/dns"
)

var (
	msgPool4k = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
)

func PackMsg(m *dns.Msg) ([]byte, *[]byte, error) {
	p := msgPool4k.Get().(*[]byte)
	b := *p
	mb, err := m.PackBuffer(b)
	if err != nil {
		msgPool4k.Put(p)
		return nil, nil, err
	}
	return mb, p, nil
}

func ReleaseMsgBufPointer(p *[]byte) {
	msgPool4k.Put(p)
}
