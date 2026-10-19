package runtimehost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/iniwex5/vowifi-go/internal/ims"
)

// Preserve identity across initial, authenticated and refreshed REGISTERs.
// The WLAN node identifier follows the original's stable SHA-256 construction;
// it is a generated compatibility identifier, not an observed Wi-Fi BSSID.
func applyIMSDeviceIdentity(cfg *ims.Config, imei string) {
	imei = strings.TrimSpace(imei)
	seed := imei
	if seed == "" {
		seed = cfg.PrivateIdentity
	}
	digest := sha256.Sum256([]byte(seed))
	node := append([]byte(nil), digest[:6]...)
	node[0] = (node[0] & 0xfe) | 0x02 // locally administered unicast address
	if cfg.RegisterHeaders == nil {
		cfg.RegisterHeaders = make(map[string]string)
	}
	if cfg.RegisterHeaders["p-access-network-info"] == "" {
		cfg.RegisterHeaders["p-access-network-info"] = `IEEE-802.11; i-wlan-node-id="` + hex.EncodeToString(node) + `"`
	}
	validIMEI := len(imei) == 15
	for _, digit := range imei {
		if digit < '0' || digit > '9' {
			validIMEI = false
			break
		}
	}
	if validIMEI {
		// RFC 7254: the IMEI URN carries TAC, SNR and a zero spare digit,
		// rather than the IMEI's printed Luhn check digit.
		cfg.SIPInstance = "urn:gsma:imei:" + imei[:8] + "-" + imei[8:14] + "-0"
		return
	}
	// Without a usable IMEI, use a stable device instance UUID (RFC 5626).
	id := digest[:16]
	id[6] = (id[6] & 0x0f) | 0x80 // RFC 9562 custom UUID version 8
	id[8] = (id[8] & 0x3f) | 0x80
	cfg.SIPInstance = fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}
