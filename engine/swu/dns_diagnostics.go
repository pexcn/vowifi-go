package swu

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// DNSQueryDiagnostic summarizes a wire query without exposing names or RDATA.
// RCode is the DNS header's four-bit response code. AnswerCount counts all
// answer records, including CNAMEs; it is not the number of usable addresses.
type DNSQueryDiagnostic struct {
	Type             string `json:"type"`
	ResponseReceived bool   `json:"response_received"`
	RCode            string `json:"rcode,omitempty"`
	AnswerCount      uint16 `json:"answer_count"`
}

const maxDNSDiagnosticQueries = 32

type dnsQueryCapture struct {
	mu        sync.Mutex
	conns     []*dnsDiagnosticConn
	truncated bool
}

func (q *dnsQueryCapture) wrap(conn net.Conn) net.Conn {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.conns) == maxDNSDiagnosticQueries {
		q.truncated = true
		return conn
	}
	c := &dnsDiagnosticConn{Conn: conn}
	q.conns = append(q.conns, c)
	return c
}

func (q *dnsQueryCapture) snapshot() ([]DNSQueryDiagnostic, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var queries []DNSQueryDiagnostic
	for _, c := range q.conns {
		c.mu.Lock()
		query, response := c.query.message(), c.response.message()
		if kind, ok := dnsQuestionType(query); ok && query[2]&0x80 == 0 {
			d := DNSQueryDiagnostic{Type: fmt.Sprint(kind)}
			if kind == 1 {
				d.Type = "A"
			} else if kind == 28 {
				d.Type = "AAAA"
			}
			responseKind, valid := dnsQuestionType(response)
			if valid && response[2]&0x80 != 0 && responseKind == kind &&
				binary.BigEndian.Uint16(query) == binary.BigEndian.Uint16(response) {
				d.ResponseReceived = true
				code := response[3] & 15
				names := [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}
				d.RCode = fmt.Sprint(code)
				if int(code) < len(names) {
					d.RCode = names[code]
				}
				d.AnswerCount = binary.BigEndian.Uint16(response[6:8])
			}
			queries = append(queries, d)
		}
		c.mu.Unlock()
	}
	return queries, q.truncated
}

// net.Resolver uses one TCP connection per exchange. Observe only its first
// frame, keeping at most the length, header and maximum-sized question prefix.
// Reads/writes, deadlines and cancellation still go to the original connection.
type dnsDiagnosticConn struct {
	net.Conn
	mu              sync.Mutex
	query, response dnsFrameCapture
}

func (c *dnsDiagnosticConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.response.add(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *dnsDiagnosticConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.query.add(p[:n])
	c.mu.Unlock()
	return n, err
}

type dnsFrameCapture struct {
	prefix   []byte
	received int
}

func (f *dnsFrameCapture) add(p []byte) {
	const maxPrefix = 2 + 12 + 255 + 4
	n := min(len(p), maxPrefix-len(f.prefix))
	f.prefix = append(f.prefix, p[:n]...)
	f.received = min(f.received+len(p), 2+65535)
}

func (f *dnsFrameCapture) message() []byte {
	if len(f.prefix) < 14 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(f.prefix))
	if length < 12 || f.received < length+2 {
		return nil
	}
	return f.prefix[2:min(length+2, len(f.prefix))]
}

func dnsQuestionType(msg []byte) (uint16, bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return 0, false
	}
	for i := 12; i < len(msg); {
		label := int(msg[i])
		i++
		if label&0xc0 == 0xc0 {
			i++ // A compression pointer terminates the encoded name.
		} else if label != 0 {
			if label > 63 {
				return 0, false
			}
			i += label
			continue
		}
		if i+4 > len(msg) {
			return 0, false
		}
		return binary.BigEndian.Uint16(msg[i : i+2]), true
	}
	return 0, false
}
