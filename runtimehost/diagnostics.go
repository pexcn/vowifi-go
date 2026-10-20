package runtimehost

import (
	"errors"
	"net"

	"github.com/iniwex5/vowifi-go/engine/swu"
	"go.uber.org/zap"
)

func swuDiagnosticLogger() func(swu.Diagnostic) {
	log := Logger()
	if !log.Core().Enabled(zap.DebugLevel) {
		return nil
	}
	return func(d swu.Diagnostic) {
		outcome := "success"
		if d.Err != nil {
			outcome = "failure"
		}
		fields := []zap.Field{
			zap.String("device_id", d.DeviceID), zap.String("trace_id", d.TraceID),
			zap.String("stage", d.Stage), zap.String("outcome", outcome),
			zap.String("epdg", d.EPDG), zap.String("proxy_id", d.ProxyID),
			zap.String("selected_peer", d.Peer), zap.String("requested_ip_stack", d.RequestedIPStack),
			zap.Int64("elapsed_ms", d.Duration.Milliseconds()),
		}
		if host, _, err := net.SplitHostPort(d.Peer); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				family := "ipv6"
				if ip.To4() != nil {
					family = "ipv4"
				}
				fields = append(fields, zap.String("selected_ip", ip.String()), zap.String("peer_ip_family", family))
			}
		}
		if d.Stage == "epdg_dns" {
			fields = append(fields, zap.String("dns_mode", d.DNSMode), zap.String("dns_target", d.DNSTarget), zap.Strings("resolved_ips", d.ResolvedIPs))
		}
		if d.Stage == "ike_handshake" {
			fields = append(fields, zap.Strings("assigned_ip_families", d.AssignedIPFamilies))
		}
		if d.NotifyType != 0 {
			fields = append(fields, zap.Uint16("notify_type", d.NotifyType), zap.String("notify_name", d.NotifyName))
		}
		if d.Err != nil {
			fields = append(fields, zap.Error(d.Err))
			var dnsErr *net.DNSError
			if errors.As(d.Err, &dnsErr) {
				// Go can report the system resolver here even when Dial routes the
				// query through SOCKS5. This is not the actual dns_target above.
				fields = append(fields, zap.String("reported_dns", dnsErr.Server), zap.Bool("dns_not_found", dnsErr.IsNotFound), zap.Bool("dns_timeout", dnsErr.IsTimeout))
			}
		}
		log.Debug("VoWiFi connection diagnostic", fields...)
	}
}
