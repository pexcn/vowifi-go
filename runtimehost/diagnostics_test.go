package runtimehost

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSWUDiagnosticsAreDebugOnlyAndKeepActualDNSSeparate(t *testing.T) {
	previous := Logger()
	t.Cleanup(func() { SetLogger(previous) })
	core, logs := observer.New(zap.InfoLevel)
	SetLogger(zap.New(core))
	cfg, err := buildSWUConfig(testRequest())
	if err != nil || cfg.OnDiagnostic != nil {
		t.Fatalf("normal logging enabled diagnostic collection: %v", err)
	}
	core, logs = observer.New(zap.DebugLevel)
	SetLogger(zap.New(core))
	req := testRequest()
	req.Proxy = &ProxyConfig{ID: "de", Enabled: true, Addr: "127.0.0.1:1080", Username: "private-user", Password: "private-password"}
	cfg, err = buildSWUConfig(req)
	if err != nil || cfg.OnDiagnostic == nil {
		t.Fatalf("DEBUG did not enable diagnostics: %v", err)
	}
	queries := []swu.DNSQueryDiagnostic{{Type: "A", ResponseReceived: true, RCode: "NXDOMAIN", AnswerCount: 0}}
	cfg.OnDiagnostic(swu.Diagnostic{
		Stage: "epdg_dns", DeviceID: "device", TraceID: "trace", EPDG: "epdg.example",
		ProxyID: "de", DNSMode: "proxy", DNSTarget: "8.8.8.8:53", Duration: 25 * time.Millisecond,
		DNSQueries: queries, DNSQueriesTruncated: true,
		Err: &net.DNSError{Err: "no such host", Name: "epdg.example", Server: "192.168.1.1:53", IsNotFound: true},
	})
	entry := logs.All()[0]
	fields := entry.ContextMap()
	if entry.Level != zap.DebugLevel || fields["device_id"] != "device" || fields["trace_id"] != "trace" || fields["proxy_id"] != "de" || fields["dns_target"] != "8.8.8.8:53" || fields["reported_dns"] != "192.168.1.1:53" || fields["dns_not_found"] != true || fields["outcome"] != "failure" {
		t.Fatalf("misleading DNS diagnostic: %+v", fields)
	}
	if !reflect.DeepEqual(fields["dns_queries"], queries) || fields["dns_queries_truncated"] != true {
		t.Fatalf("missing wire DNS diagnostics: %+v", fields)
	}
	cfg.OnDiagnostic(swu.Diagnostic{
		Stage: "ike_handshake", DeviceID: "device", TraceID: "trace", Peer: "192.0.2.10:4500",
		RequestedIPStack: "ipv4v6", NotifyType: 36, NotifyName: "INTERNAL_ADDRESS_FAILURE",
		Err: &net.OpError{Op: "read", Err: net.ErrClosed},
	})
	fields = logs.All()[1].ContextMap()
	if fields["selected_ip"] != "192.0.2.10" || fields["peer_ip_family"] != "ipv4" || fields["requested_ip_stack"] != "ipv4v6" || fields["notify_type"] != uint16(36) || fields["notify_name"] != "INTERNAL_ADDRESS_FAILURE" {
		t.Fatalf("missing IKE diagnostic: %+v", fields)
	}
	encoded, err := json.Marshal(logs.All())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{req.Prepared.Profile.IMSI, cfg.NAI, req.Proxy.Username, req.Proxy.Password, "password", "username", "rand", "autn", "integrity_key", "encryption_key"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("diagnostic exposed authentication data: %q", secret)
		}
	}
}
