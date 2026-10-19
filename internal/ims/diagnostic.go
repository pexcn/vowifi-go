package ims

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var registrationRedactions = []struct {
	pattern *regexp.Regexp
	value   string
}{
	{regexp.MustCompile(`(?i)(sips?:)[^\s<>"@;,]+@`), `${1}redacted@`},
	{regexp.MustCompile(`(?i)(\+sip\.instance\s*=\s*)"[^"]*"`), `${1}"redacted"`},
	{regexp.MustCompile(`(?i)(i-wlan-node-id\s*=\s*)("[^"]*"|[^;\s]+)`), `${1}"redacted"`},
	{regexp.MustCompile(`[0-9]{6,}`), `redacted`},
	// Also suppress long tokens in free-form Warning/Reason text.
	{regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`), `redacted`},
}

// Record only failed registration metadata. Authentication values and message
// bodies are never logged; unknown extension-header values are omitted.
func registrationDiagnostic(m *message) string {
	redact := func(value string) string {
		for _, r := range registrationRedactions {
			value = r.pattern.ReplaceAllString(value, r.value)
		}
		if len(value) > 512 {
			value = value[:512] + "..."
		}
		return value
	}
	var b strings.Builder
	b.WriteString(redact(m.Start) + "\n")
	keys := make([]string, 0, len(m.Headers))
	for key := range m.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range m.Headers[key] {
			switch key {
			case "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate", "authentication-info":
				value = "[authentication value omitted]"
			case "via", "from", "to", "contact", "cseq", "call-id", "max-forwards", "expires", "min-expires", "supported", "require", "proxy-require", "allow", "accept", "user-agent", "content-length", "content-type", "security-client", "security-server", "security-verify", "p-access-network-info", "warning", "reason", "server", "retry-after", "unsupported":
				value = redact(value)
			default:
				value = "[extension value omitted]"
			}
			fmt.Fprintf(&b, "%s: %s\n", key, value)
		}
	}
	if len(m.Body) > 0 {
		fmt.Fprintf(&b, "[body omitted: %d bytes]\n", len(m.Body))
	}
	return b.String()
}
