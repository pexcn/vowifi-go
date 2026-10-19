// Package ims implements the terminal SIP layer used inside an authenticated SWu tunnel.
package ims

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxMessage = 1 << 20

type message struct {
	Start   string
	Headers map[string][]string
	Body    []byte
	// reply preserves the receiving protected server port pair for SIP responses.
	reply func([]byte) error
}

func (m *message) get(k string) string {
	v := m.Headers[strings.ToLower(k)]
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
func (m *message) set(k, v string) {
	if m.Headers == nil {
		m.Headers = make(map[string][]string)
	}
	m.Headers[strings.ToLower(k)] = []string{v}
}
func (m *message) add(k, v string) {
	if m.Headers == nil {
		m.Headers = make(map[string][]string)
	}
	m.Headers[strings.ToLower(k)] = append(m.Headers[strings.ToLower(k)], v)
}
func (m *message) status() int {
	fields := strings.Fields(m.Start)
	if len(fields) < 2 || fields[0] != "SIP/2.0" {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}
func (m *message) method() string {
	if m.status() != 0 {
		return ""
	}
	f := strings.Fields(m.Start)
	if len(f) > 0 {
		return f[0]
	}
	return ""
}
func headerName(k string) string {
	switch k {
	case "i":
		return "call-id"
	case "f":
		return "from"
	case "t":
		return "to"
	case "v":
		return "via"
	case "l":
		return "content-length"
	case "c":
		return "content-type"
	case "m":
		return "contact"
	}
	return k
}
func readMessage(r *bufio.Reader) (*message, error) {
	// RFC 5626 CRLF keepalives are consumed without becoming transactions.
	var line string
	var err error
	total := 0
	for {
		line, err = readLine(r)
		if err != nil {
			return nil, err
		}
		if line != "" {
			break
		}
	}
	if len(line) > 8192 {
		return nil, errors.New("SIP start line too long")
	}
	total += len(line)
	f := strings.Fields(line)
	if len(f) < 3 {
		return nil, errors.New("invalid SIP start line")
	}
	if f[0] != "SIP/2.0" && f[len(f)-1] != "SIP/2.0" {
		return nil, errors.New("unsupported SIP version")
	}
	m := &message{Start: line, Headers: make(map[string][]string)}
	last := ""
	for {
		line, err = readLine(r)
		if err != nil {
			return nil, err
		}
		total += len(line)
		if total > 65536 {
			return nil, errors.New("SIP headers too large")
		}
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return nil, errors.New("orphan SIP header continuation")
			}
			vs := m.Headers[last]
			vs[len(vs)-1] += " " + strings.TrimSpace(line)
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return nil, errors.New("malformed SIP header")
		}
		last = headerName(strings.ToLower(strings.TrimSpace(line[:i])))
		m.add(last, strings.TrimSpace(line[i+1:]))
	}
	n := 0
	if v := m.get("content-length"); v != "" {
		n, err = strconv.Atoi(v)
		if err != nil || n < 0 || n > maxMessage {
			return nil, errors.New("invalid SIP Content-Length")
		}
		for _, x := range m.Headers["content-length"] {
			if x != v {
				return nil, errors.New("conflicting SIP Content-Length")
			}
		}
	}
	m.Body = make([]byte, n)
	if _, err = io.ReadFull(r, m.Body); err != nil {
		return nil, err
	}
	return m, nil
}
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, e := r.ReadSlice('\n')
		if len(line)+len(part) > 65536 {
			return "", errors.New("SIP line too long")
		}
		line = append(line, part...)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			return "", e
		}
		break
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", errors.New("SIP requires CRLF")
	}
	line = line[:len(line)-2]
	if bytes.ContainsAny(line, "\r\x00") {
		return "", errors.New("invalid SIP control character")
	}
	return string(line), nil
}
func (m *message) bytes() ([]byte, error) {
	if strings.ContainsAny(m.Start, "\r\n") {
		return nil, errors.New("SIP start line injection")
	}
	var b bytes.Buffer
	b.WriteString(m.Start + "\r\n")
	for k, vs := range m.Headers {
		if k == "content-length" {
			continue
		}
		if strings.ContainsAny(k, "\r\n:") {
			return nil, errors.New("SIP header name injection")
		}
		for _, v := range vs {
			if strings.ContainsAny(v, "\r\n") {
				return nil, errors.New("SIP header injection")
			}
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(m.Body))
	b.Write(m.Body)
	return b.Bytes(), nil
}
func response(req *message, code int, reason string) *message {
	m := &message{Start: fmt.Sprintf("SIP/2.0 %d %s", code, reason), Headers: make(map[string][]string), reply: req.reply}
	for _, k := range []string{"via", "from", "to", "call-id", "cseq"} {
		for _, v := range req.Headers[k] {
			m.add(k, v)
		}
	}
	return m
}
func splitQuoted(s string, sep byte) ([]string, error) {
	var out []string
	start := 0
	quote, escape := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if quote && c == '\\' {
			escape = true
			continue
		}
		if c == '"' {
			quote = !quote
		}
		if c == sep && !quote {
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if quote || escape {
		return nil, errors.New("unterminated quoted parameter")
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out, nil
}
func parameters(s string, sep byte) (map[string]string, error) {
	ps, e := splitQuoted(s, sep)
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, p := range ps {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		if strings.HasPrefix(v, "\"") {
			v, e = strconv.Unquote(v)
			if e != nil {
				return nil, e
			}
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate parameter %s", k)
		}
		out[k] = v
	}
	return out, nil
}
