package runtimehost

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

const (
	userNetworkMTU = 1280
	// IMS transport ESP adds SPI/sequence, IV, padding, trailer and ICV
	// inside the SWu tunnel. Leave room for it above the IP stack's MTU.
	imsESPHeadroom = 80
)

var errUnsupportedCarrierProposals = errors.New("carrier has no supported IKE/ESP pair")

// Select a supported pair from the caller's resolved carrier proposals. The
// current engine shares the selected key size/integrity profile across IKE/Child SA;
// it must not silently substitute an algorithm outside either offer.
func buildSWUConfig(req StartRequest) (swu.Config, error) {
	p := req.Prepared
	params := p.EffectiveCarrier.Parameters
	mnc := p.Profile.MNC
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	epdg := p.EPDGAddr
	if params.EPDGPort > 0 {
		if params.EPDGPort > 65535 {
			return swu.Config{}, errors.New("invalid carrier ePDG port")
		}
		if _, _, err := net.SplitHostPort(epdg); err != nil {
			epdg = net.JoinHostPort(strings.Trim(epdg, "[]"), strconv.Itoa(params.EPDGPort))
		}
	}
	cfg := swu.Config{DeviceID: req.DeviceID, TraceID: req.TraceID, EPDGAddr: epdg, DataplaneMode: req.Dataplane.Mode, Proxy: toSWUProxy(req.Proxy), Identity: p.IMSIdentity, SIM: req.SIM, NAI: fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", p.Profile.IMSI, mnc, p.Profile.MCC), APN: params.APN, DPDInterval: time.Duration(params.DPDIntervalSeconds) * time.Second}
	cfg.OnDiagnostic = swuDiagnosticLogger()
	// SWu peers may authenticate solely through mutual EAP-AKA (RFC 5998).
	// If a peer sends certificate AUTH instead, the engine still verifies it.
	cfg.EAPOnlyAuthentication = true
	cfg.EAPReauth = req.AuthenticationContext
	cfg.AKAPrimeNetworkName = params.EAPAKAPrimeNetworkName
	cfg.RequireAKAPrime = params.EAPAKAPrimeRequired
	cfg.EPDGFailover = true
	cfg.MTU = userNetworkMTU + imsESPHeadroom
	if cfg.APN == "" {
		cfg.APN = "ims"
	}
	cfg.IPStack = params.IPStack
	cfg.DNSServer = params.DNSServer
	cfg.AKAChallengeMode = params.AKAChallengeMode
	cfg.NATKeepalive = time.Duration(params.NATKeepaliveSeconds) * time.Second
	if cfg.RequireAKAPrime && strings.HasPrefix(cfg.NAI, "0") {
		cfg.NAI = "6" + cfg.NAI[1:]
	}
	ikes, esps := params.IKEProposals, params.ESPProposals
	if len(ikes) == 0 {
		ikes = []string{"aes128-sha256-modp2048"}
	}
	if len(esps) == 0 {
		esps = []string{"aes128-sha256"}
	}
	var profiles []swu.IKEProfile
	for _, proposal := range ikes {
		profile, esp, ok := parseCarrierIKEProfile(proposal)
		if !ok {
			continue
		}
		for _, child := range esps {
			if strings.EqualFold(strings.TrimSpace(child), esp) {
				profiles = append(profiles, profile)
				break
			}
		}
	}
	if len(profiles) > 0 {
		cfg.Encryption = profiles[0].Encryption
		cfg.IKEFragmentMTU = params.IKEFragmentMTU
		cfg.IKEFragmentPMTU = params.IKEFragmentPMTU
		cfg.EncryptionKeyBits, cfg.PRF, cfg.Integrity, cfg.DHGroup = profiles[0].EncryptionKeyBits, profiles[0].PRF, profiles[0].Integrity, profiles[0].DHGroup
		cfg.IKEAlternatives = profiles[1:]
		return cfg, nil
	}
	return swu.Config{}, fmt.Errorf("%w (requires a supported authenticated IKE/ESP pair): IKE %v ESP %v", errUnsupportedCarrierProposals, ikes, esps)
}

func parseCarrierIKEProfile(raw string) (swu.IKEProfile, string, bool) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(raw)), "-")
	if len(parts) != 3 && len(parts) != 4 {
		return swu.IKEProfile{}, "", false
	}
	var p swu.IKEProfile
	switch parts[0] {
	case "aes128", "aes128gcm16":
		p.EncryptionKeyBits = 128
	case "aes256", "aes256gcm16":
		p.EncryptionKeyBits = 256
	default:
		return p, "", false
	}
	gcm := strings.HasSuffix(parts[0], "gcm16")
	prf := func(v string) vc.PRF {
		switch strings.TrimPrefix(v, "prf") {
		case "sha1":
			return vc.PRFSHA1
		case "sha256":
			return vc.PRFSHA256
		case "sha384":
			return vc.PRFSHA384
		case "sha512":
			return vc.PRFSHA512
		}
		return 0
	}
	esp := parts[0] + "-" + parts[1]
	if gcm {
		if len(parts) != 3 || !strings.HasPrefix(parts[1], "prf") {
			return p, "", false
		}
		p.Encryption = vc.AESGCM16
		p.PRF = prf(parts[1])
		esp = parts[0]
	} else {
		switch parts[1] {
		case "sha1":
			p.Integrity = vc.HMACSHA196
		case "sha256":
			p.Integrity = vc.HMACSHA256128
		case "sha384":
			p.Integrity = vc.HMACSHA384192
		case "sha512":
			p.Integrity = vc.HMACSHA512256
		default:
			return p, "", false
		}
		p.PRF = prf(parts[1])
		if len(parts) == 4 {
			p.PRF = prf(parts[2])
		}
	}
	if p.PRF.Size() == 0 {
		return p, "", false
	}
	switch parts[len(parts)-1] {
	case "modp2048":
		p.DHGroup = 14
	case "modp1024":
		p.DHGroup = 2
	case "ecp256":
		p.DHGroup = 19
	case "ecp384":
		p.DHGroup = 20
	case "ecp521":
		p.DHGroup = 21
	default:
		return p, "", false
	}
	return p, esp, true
}

func applyIMSProfile(cfg *ims.Config, params carrier.PresetParameters, security *ims.SecurityParameters) error {
	if params.IMSRealm != "" {
		cfg.Realm = params.IMSRealm
	}
	if params.IMSPCSCF != "" {
		cfg.PCSCF = []string{params.IMSPCSCF}
	}
	switch params.IMSTransport {
	case "", "auto":
		// REGISTER with AKA and security headers can exceed a single tunnel
		// datagram. Prefer TCP for auto so SIP can be segmented without IP
		// fragmentation (RFC 3261 section 18.1.1).
		cfg.Transport = "tcp"
	case "udp":
		cfg.Transport = "udp"
	case "tcp":
		cfg.Transport = "tcp"
	default:
		return fmt.Errorf("unsupported IMS transport %q", params.IMSTransport)
	}
	cfg.UserAgent = params.IMSUserAgent
	if params.IMSTCPKeepaliveSeconds > 0 {
		cfg.KeepAlive = time.Duration(params.IMSTCPKeepaliveSeconds) * time.Second
	}
	template := params.IMSRegisterTemplate
	policy := template.RegisterPolicy
	if policy.TemporaryStatusCodes != nil {
		cfg.TemporaryStatusCodes = append([]int{}, policy.TemporaryStatusCodes...)
	}
	if policy.ForbiddenStatusCodes != nil {
		cfg.ForbiddenStatusCodes = append([]int{}, policy.ForbiddenStatusCodes...)
	}
	if policy.TemporaryRetrySeconds > 0 {
		if uint64(policy.TemporaryRetrySeconds) > uint64((1<<63-1)/time.Second) {
			return errors.New("invalid IMS retry interval")
		}
		cfg.RecoveryInitial = time.Duration(policy.TemporaryRetrySeconds) * time.Second
	}
	if template.UsePlainDigestPlaceholder != nil {
		cfg.UsePlainDigestPlaceholder = *template.UsePlainDigestPlaceholder
	}
	headers := map[string]string{}
	if template.SupportedHeader != "" {
		headers["supported"] = template.SupportedHeader
	}
	if template.AllowHeader != "" {
		headers["allow"] = template.AllowHeader
	}
	if template.FixedPANI != "" {
		headers["p-access-network-info"] = template.FixedPANI
	}
	cfg.RegisterHeaders = headers
	// Advertise only capabilities actually implemented by this open stack.
	cfg.ContactParameters = ""
	if template.AccessType != "" {
		cfg.ContactParameters = "+g.3gpp.accesstype=" + strconv.Quote(template.AccessType) + ";"
	}
	cfg.ContactParameters += "+g.3gpp.smsip;audio"
	if template.ICSIReference != "" {
		cfg.ContactParameters += `; +g.3gpp.icsi-ref="` + template.ICSIReference + `"`
	}
	if template.SecAgreeMode == "none" || template.SecAgreeMode == "disabled" {
		cfg.SecurityClient = nil
		cfg.SecurityClientAlternatives = nil
		return nil
	}
	mechanisms := template.SecurityClientMechanisms
	if len(mechanisms) == 0 {
		cfg.SecurityClient = security
		cfg.SecurityClientAlternatives = nil
		return nil
	}
	cfg.SecurityClient = nil
	cfg.SecurityClientAlternatives = nil
	seen := make(map[string]bool)
	for _, m := range mechanisms {
		if (m.Algorithm == "hmac-sha-1-96" || m.Algorithm == "hmac-md5-96") && (m.EncryptionAlgorithm == "aes-cbc" || m.EncryptionAlgorithm == "null") && (m.Protocol == "" || m.Protocol == "esp") && (m.Mode == "" || m.Mode == "trans") {
			key := m.Algorithm + "/" + m.EncryptionAlgorithm
			if seen[key] {
				continue
			}
			seen[key] = true
			offer := *security
			offer.Algorithm, offer.Encryption = m.Algorithm, m.EncryptionAlgorithm
			if cfg.SecurityClient == nil {
				*security = offer
				cfg.SecurityClient = security
			} else {
				cfg.SecurityClientAlternatives = append(cfg.SecurityClientAlternatives, offer)
			}
		}
	}
	if cfg.SecurityClient != nil {
		return nil
	}
	return errors.New("carrier IMS template has no supported ipsec-3gpp mechanism")
}
