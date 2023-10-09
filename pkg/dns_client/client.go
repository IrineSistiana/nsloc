package dnsClient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrQueryCollision  = errors.New("query tuple collision")
	ErrClientClosed    = errors.New("client closed")
	ErrInvalidQuestion = errors.New("invalid question")
)

type Client struct {
	c *net.UDPConn

	m     sync.Mutex
	queue map[queryTuple]chan Resp // queue that waiting for response

	closeOnce   sync.Once
	closeNotify chan struct{}
	closeErr    error

	nextQid uint32
}

type Resp struct {
	From netip.AddrPort
	Msg  *dns.Msg
}

type queryTuple struct {
	id       uint16
	question dns.Question
}

func New(c *net.UDPConn) *Client {
	dc := &Client{c: c,
		queue:       make(map[queryTuple]chan Resp),
		closeNotify: make(chan struct{}),
	}
	go dc.readLoop()
	return dc
}

// Query sends a query to the server through UDP.
// It waits until the response received or ctx was done.
// Note: q with identical id and question can not be query
// concurrently. Otherwise, Query will return ErrQueryCollision.
// q must have and only have one question.
func (c *Client) Query(ctx context.Context, q *dns.Msg, addr netip.AddrPort) (*dns.Msg, error) {
	if len(q.Question) != 1 {
		return nil, ErrInvalidQuestion
	}

	resChan := make(chan Resp)
	question := q.Question[0]
	if ok := c.Listen(q.Id, question, resChan); !ok {
		return nil, ErrQueryCollision
	}
	defer c.StopListen(q.Id, question)

	qb, bp, err := PackMsg(q)
	if err != nil {
		return nil, fmt.Errorf("failed to pack query, %w", err)
	}
	defer ReleaseMsgBufPointer(bp)

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	retryTicker := time.NewTicker(time.Second)
	defer retryTicker.Stop()

send:
	_, err = c.c.WriteToUDPAddrPort(qb, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to send query, %w", err)
	}

	select {
	case <-retryTicker.C:
		goto send
	case resp := <-resChan:
		return resp.Msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeNotify:
		return nil, c.closeErr
	}
}

// Listen register resChan to the queue. If there is a collision, Listen returns false.
// Note: c.NextQid() can return a increasing id that can make the collision nearly impossible.
func (c *Client) Listen(id uint16, q dns.Question, resChan chan Resp) bool {
	qt := queryTuple{
		id:       id,
		question: q,
	}
	c.m.Lock()
	if cc, collision := c.queue[qt]; collision && cc != resChan {
		c.m.Unlock()
		return false
	}
	c.queue[qt] = resChan
	c.m.Unlock()
	return true
}

// StopListen remove a registered listener from queue.
// If no such listener, StopListen is noop.
func (c *Client) StopListen(id uint16, q dns.Question) {
	qt := queryTuple{
		id:       id,
		question: q,
	}
	c.m.Lock()
	delete(c.queue, qt)
	c.m.Unlock()
}

// WriteTo calls inner UDP connection's WriteToUDPAddrPort method.
func (c *Client) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	return c.c.WriteToUDPAddrPort(b, addr)
}

// NextQid returns a increasing uint16 counter. This is a helper func for dns query id
// to avoid query collision.
func (c *Client) NextQid() uint16 {
	return uint16(atomic.AddUint32(&c.nextQid, 1))
}

func (c *Client) readLoop() {
	b := make([]byte, 4096)
	for {
		n, from, err := c.c.ReadFromUDPAddrPort(b)
		if err != nil {
			c.closeWithErr(err)
			return
		}

		r := new(dns.Msg)
		if err := r.Unpack(b[:n]); err != nil {
			continue // Ignore invalid udp msg.
		}
		if !r.Response || len(r.Question) != 1 {
			continue
		}

		qt := queryTuple{
			id:       r.Id,
			question: r.Question[0],
		}
		c.m.Lock()
		resChan := c.queue[qt]
		c.m.Unlock()
		if resChan != nil {
			select {
			case resChan <- Resp{From: from, Msg: r}: // resChan should have buffer.
			default:
			}
		}
	}
}

func (c *Client) closeWithErr(err error) {
	if err == nil {
		err = ErrClientClosed
	}
	c.closeOnce.Do(func() {
		_ = c.c.Close()
		c.closeErr = err
		close(c.closeNotify)
	})
}

func (c *Client) Close() error {
	c.closeWithErr(nil)
	return nil
}
