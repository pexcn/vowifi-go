package e911

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20
const operationTimeout = 45 * time.Second

type defaultHTTPClient struct{ client *http.Client }

func NewDefaultHTTPClient() HTTPClient {
	return defaultHTTPClient{client: &http.Client{
		Timeout: 20 * time.Second,
		// Do not forward subscriber identities, AKA responses or tokens to a redirect.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
func (c defaultHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	ctx := context.Background()
	if req != nil && req.Context != nil {
		ctx = req.Context
	}
	return c.DoContext(ctx, req)
}
func (c defaultHTTPClient) DoContext(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	if req == nil {
		return nil, errors.New("nil e911 http request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := validateHTTPS(req.URL); err != nil {
		return nil, err
	}
	if len(req.Body) > maxBodyBytes {
		return nil, errors.New("e911 request exceeds body limit")
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	r, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for _, h := range req.Headers {
		r.Header.Add(h.Key, h.Value)
	}
	client := c.client
	if client == nil {
		client = NewDefaultHTTPClient().(defaultHTTPClient).client
	}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := readBounded(resp.Body)
	if err != nil {
		return nil, err
	}
	out := &HTTPResponse{StatusCode: resp.StatusCode, Body: b}
	for k, values := range resp.Header {
		for _, v := range values {
			out.Headers = append(out.Headers, HeaderPair{k, v})
		}
	}
	return out, nil
}
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBodyBytes {
		return nil, errors.New("e911 response exceeds body limit")
	}
	return b, nil
}
func validateHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return errors.New("e911 requires an absolute HTTPS URL without credentials or fragment")
	}
	return nil
}

// The host websheet broker resolves DNS and checks the connected peer IP on
// every redirect. This check rejects unsafe literal/local hostnames before any
// websheet is returned, without contacting DNS during injected offline tests.
func validateWebsheet(raw, policy string) error {
	if policy != "" && policy != "public_https" {
		return fmt.Errorf("unsupported websheet host policy %q", policy)
	}
	if err := validateHTTPS(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return errors.New("e911 websheet must use a public host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
			return errors.New("e911 websheet must use a public address")
		}
	}
	return nil
}
