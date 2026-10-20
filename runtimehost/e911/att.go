package e911

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/iniwex5/vowifi-go/engine/eap"
)

var requestSequence atomic.Uint64

type authAction struct {
	AuthType     string `json:"auth-type"`
	ActionName   string `json:"action-name"`
	SubscriberID string `json:"subscriber-id"`
	RequestID    uint64 `json:"request-id"`
	UniqueID     string `json:"unique-id"`
	Token        string `json:"token,omitempty"`
}
type entitlementAction struct {
	EntitlementNames []string `json:"entitlement-names"`
	ActionName       string   `json:"action-name"`
	RequestID        uint64   `json:"request-id"`
}
type phoneAction struct {
	SIPUsername string `json:"sip-username"`
	ActionName  string `json:"action-name"`
	RequestID   uint64 `json:"request-id"`
	DisplayName string `json:"display-name"`
}
type challengeAction struct {
	ActionName string `json:"action-name"`
	Payload    string `json:"payload"`
	RequestID  uint64 `json:"request-id"`
}

// JSON names and action types are observed in the target's Go type descriptors.
type responseItem struct {
	Status                *int   `json:"status"`
	ResponseID            uint64 `json:"response-id"`
	Token                 string `json:"token"`
	Challenge             string `json:"challenge"`
	AddressUpdateURL      string `json:"address-update-url"`
	AddressUpdatePostData string `json:"address-update-url-post-data"`
}

func nextRequestID() uint64 { return requestSequence.Add(1) }

func initialActions(id Identity, permanentIdentity, token string) ([]any, map[uint64]bool) {
	subscriberPacket, _ := (eap.Packet{Code: eap.Response, Identifier: 0, Type: eap.Identity, Data: []byte(permanentIdentity)}).Marshal()
	a := authAction{"EAP-AKA", "getAuthentication", base64.StdEncoding.EncodeToString(subscriberPacket), nextRequestID(), strings.TrimSpace(id.IMEI), token}
	out := []any{a}
	expected := map[uint64]bool{a.RequestID: true}
	if name := strings.TrimSpace(id.SIPUsername); name != "" {
		p := phoneAction{name, "getPhoneServicesAccountStatus", nextRequestID(), strings.TrimSpace(id.DisplayName)}
		out = append(out, p)
		expected[p.RequestID] = true
	}
	ent := entitlementAction{[]string{"VoWiFi"}, "getEntitlement", nextRequestID()}
	out = append(out, ent)
	expected[ent.RequestID] = true
	return out, expected
}
func startATT(ctx context.Context, req Request) (WebsheetRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	id := req.Identity
	id.IMSI = strings.TrimSpace(id.IMSI)
	id.MCC = strings.TrimSpace(id.MCC)
	id.MNC = strings.TrimSpace(id.MNC)
	if !digits(id.IMSI, 5, 15) || !digits(id.MCC, 3, 3) || !digits(id.MNC, 2, 3) {
		return WebsheetRequest{}, ErrIdentityUnavailable
	}
	if len(id.MNC) == 2 {
		id.MNC = "0" + id.MNC
	}
	permanent := fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", id.IMSI, id.MNC, id.MCC)
	endpoint := strings.TrimSpace(req.Carrier.E911.EntitlementURL)
	if endpoint == "" {
		return WebsheetRequest{}, ErrWebsheetUnavailable
	}
	if err := validateHTTPS(endpoint); err != nil {
		return WebsheetRequest{}, err
	}
	client := req.Client
	if req.Proxy != nil {
		if client != nil {
			return WebsheetRequest{}, errors.New("E911 proxy cannot be combined with a custom HTTP client")
		}
		proxied, err := NewHTTPClientWithProxy(*req.Proxy)
		if err != nil {
			return WebsheetRequest{}, err
		}
		defer proxied.CloseIdleConnections()
		client = proxied
	}
	if client == nil {
		client = NewDefaultHTTPClient()
	}
	aka := &eap.Client{Identity: permanent, Provider: req.AKAProvider, Preference: req.Carrier.AKAAppPreference}
	actions, expected := initialActions(id, permanent, strings.TrimSpace(id.CachedToken))
	tokenRefetched := false
	for round := 0; round < 8; round++ {
		if err := ctx.Err(); err != nil {
			return WebsheetRequest{}, err
		}
		responses, err := runActions(ctx, client, req.Trace, endpoint, actions, expected)
		if err != nil {
			return WebsheetRequest{}, err
		}
		var challenge, webURL, postData, token string
		for _, r := range responses {
			if r.Challenge != "" {
				if challenge != "" {
					return WebsheetRequest{}, errors.New("multiple entitlement challenges")
				}
				challenge = r.Challenge
			}
			if r.Token != "" {
				token = r.Token
			}
			if r.AddressUpdateURL != "" || r.AddressUpdatePostData != "" {
				if webURL != "" {
					return WebsheetRequest{}, errors.New("multiple entitlement websheets")
				}
				webURL = strings.TrimSpace(r.AddressUpdateURL)
				postData = r.AddressUpdatePostData
			}
		}
		if challenge != "" {
			if req.AKAProvider == nil {
				return WebsheetRequest{}, ErrChallengeNotImplemented
			}
			packet, err := base64.StdEncoding.DecodeString(strings.TrimSpace(challenge))
			if err != nil {
				return WebsheetRequest{}, fmt.Errorf("decode entitlement challenge: %w", err)
			}
			p, err := eap.Parse(packet)
			if err != nil {
				return WebsheetRequest{}, fmt.Errorf("parse entitlement challenge: %w", err)
			}
			// Only classic EAP-AKA is implemented; a challenge of another type must
			// not be mistaken for authenticated provisioning.
			if p.Code != eap.Request || p.Type != eap.AKA {
				return WebsheetRequest{}, ErrChallengeNotImplemented
			}
			payload, _, err := aka.Handle(ctx, packet)
			if err != nil {
				return WebsheetRequest{}, fmt.Errorf("entitlement EAP-AKA: %w", err)
			}
			n := nextRequestID()
			actions = []any{challengeAction{"postChallenge", base64.StdEncoding.EncodeToString(payload), n}}
			expected = map[uint64]bool{n: true}
			continue
		}
		if webURL != "" {
			if strings.TrimSpace(postData) == "" {
				return WebsheetRequest{}, ErrWebsheetUnavailable
			}
			if err := validateWebsheet(webURL, strings.TrimSpace(req.Carrier.E911.WebsheetHostPolicy)); err != nil {
				return WebsheetRequest{}, fmt.Errorf("carrier websheet: %w", err)
			}
			// The HTTP channel and (when challenged) AKA AT_MAC authenticate bootstrap.
			// This result is a websheet handoff, never a claim of address verification.
			cfg := req.Carrier.E911
			title := strings.TrimSpace(cfg.Title)
			if title == "" {
				title = "Emergency Address"
			}
			return WebsheetRequest{URL: webURL, UserData: postData, ContentType: "application/x-www-form-urlencoded", Title: title}, nil
		}
		if token != "" && !tokenRefetched {
			tokenRefetched = true
			actions, expected = initialActions(id, permanent, token)
			continue
		}
		return WebsheetRequest{}, ErrWebsheetUnavailable
	}
	return WebsheetRequest{}, errors.New("entitlement exchange exceeded 8 requests")
}
func digits(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func runActions(ctx context.Context, client HTTPClient, trace TraceSink, endpoint string, actions []any, expected map[uint64]bool) ([]responseItem, error) {
	plain, err := json.Marshal(actions)
	if err != nil {
		return nil, err
	}
	if len(plain) > maxBodyBytes {
		return nil, errors.New("entitlement request exceeds body limit")
	}
	var body bytes.Buffer
	w := gzip.NewWriter(&body)
	if _, err = w.Write(plain); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	req := &HTTPRequest{Method: "POST", URL: endpoint, Context: ctx, Body: body.Bytes(), Headers: []HeaderPair{
		{"accept", "application/json"}, {"content-type", "application/json"},
		{"accept-encoding", "gzip"}, {"x-protocol-version", "2"}, {"content-encoding", "gzip"},
		{"user-agent", "Entitlement/2.0 (iPhone) iOS/18.7.1"}, {"accept-language", "zh-Hans-GB"},
	}}
	if trace != nil {
		trace.Request(req)
	}
	var resp *HTTPResponse
	if c, ok := client.(ContextHTTPClient); ok {
		resp, err = c.DoContext(ctx, req)
	} else {
		resp, err = client.Do(req)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if trace != nil {
			trace.Error(req, err)
		}
		return nil, err
	}
	if resp == nil {
		err = errors.New("nil entitlement HTTP response")
		if trace != nil {
			trace.Error(req, err)
		}
		return nil, err
	}
	if trace != nil {
		trace.Response(req, resp)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("entitlement HTTP status %d", resp.StatusCode)
	}
	if len(resp.Body) > maxBodyBytes {
		return nil, errors.New("entitlement response exceeds body limit")
	}
	data := resp.Body
	// The original detects gzip by magic bytes; this also works when a legacy
	// host adapter omits response headers, or net/http already decompressed it.
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		data, err = readBounded(r)
		closeErr := r.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	var out []responseItem
	if err = json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse entitlement JSON: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("empty entitlement response")
	}
	seen := make(map[uint64]bool)
	for _, r := range out {
		if !expected[r.ResponseID] || seen[r.ResponseID] {
			return nil, errors.New("unmatched or duplicate entitlement response-id")
		}
		seen[r.ResponseID] = true
		// TS43 successful action = 1000; 1003 requests EAP authentication. Keep
		// failure payloads (even those with a URL/token) from becoming success.
		if r.Status == nil || *r.Status != 1000 && (*r.Status != 1003 || r.Challenge == "") {
			return nil, fmt.Errorf("entitlement action %d rejected", r.ResponseID)
		}
	}
	return out, nil
}
