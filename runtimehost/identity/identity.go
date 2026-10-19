package identity

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pexcn/vowifi-go/runtimehost/carrier"
)

const (
	IMSIdentitySourceISIM      = "isim"
	IMSIdentitySourceGenerated = "generated"
	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"

	isimAIDPrefix = "A0000000871004"
	efIMPI        = "6F02"
	efDOMAIN      = "6F03"
	efIMPU        = "6F04"
)

type Profile struct {
	IMSI string
	MCC  string
	MNC  string
	IMEI string
	SMSC string
}

type Identity struct {
	IMPI   string
	IMPU   []string
	Domain string
}

type IMSIdentityResolution struct {
	RequestedSource  string
	ActualSource     string
	AKAAppPreference string
	Applied          bool
	IMPI             string
	IMPU             string
	Domain           string
}

type CarrierConfig = carrier.EffectiveCarrierConfig

type PreparedSession struct {
	Profile            Profile
	IMSIdentity        IMSIdentityResolution
	IdentityIMEISource string
	EPDGAddr           string
	EPDGSource         string
	EffectiveCarrier   CarrierConfig
}

type PrepareStartInput struct {
	DeviceID            string
	Profile             Profile
	RuntimeEPDGOverride string
	Access              interface {
		GetISIMIdentity() (Identity, error)
	}
}

type logicalChannelAccess interface {
	OpenLogicalChannel(string) (int, error)
	CloseLogicalChannel(int) error
	TransmitAPDU(int, string) (string, error)
}

type logicalChannelAIDResolver interface {
	ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error)
}

func NormalizeProfile(p Profile) Profile {
	p.IMSI = strings.TrimSpace(p.IMSI)
	p.MCC = strings.TrimSpace(p.MCC)
	p.MNC = strings.TrimSpace(p.MNC)
	p.IMEI = strings.TrimSpace(p.IMEI)
	p.SMSC = strings.TrimSpace(p.SMSC)
	if p.MCC == "" && len(p.IMSI) >= 3 {
		p.MCC = p.IMSI[:3]
	}
	return p
}

func PrepareStart(input PrepareStartInput) (PreparedSession, error) {
	profile := NormalizeProfile(input.Profile)
	if profile.IMSI == "" {
		return PreparedSession{}, fmt.Errorf("IMSI 为空，无法准备 VoWiFi 启动画像")
	}
	if profile.MCC == "" || profile.MNC == "" {
		return PreparedSession{}, fmt.Errorf("缺少 SIM 归属 MCC/MNC，无法准备 VoWiFi 启动画像")
	}

	carrierCfg := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: profile.MCC, MNC: profile.MNC})
	prepared := PreparedSession{
		Profile:            profile,
		IdentityIMEISource: "",
		EffectiveCarrier:   carrierCfg,
	}
	// Stable model-based IMEI generation is not yet reconstructed; retain the
	// caller-provided IMEI and describe its actual source truthfully.
	if profile.IMEI != "" {
		prepared.IdentityIMEISource = "input"
	}

	requestedSource := strings.TrimSpace(carrierCfg.RequestedSource)
	if requestedSource == "" {
		requestedSource = IMSIdentitySourceGenerated
	}
	akaPreference := strings.TrimSpace(carrierCfg.AKAAppPreference)
	if akaPreference == "" {
		akaPreference = AKAAppPreferenceUSIM
	}

	if requestedSource == IMSIdentitySourceISIM {
		if input.Access == nil {
			return PreparedSession{}, fmt.Errorf("ISIM 身份不可用: identity reader unavailable")
		}
		id, err := input.Access.GetISIMIdentity()
		if err != nil {
			return PreparedSession{}, fmt.Errorf("读取 ISIM 身份失败: %w", err)
		}
		if !completeIdentity(id) {
			return PreparedSession{}, fmt.Errorf("ISIM 身份不完整: IMPI/IMPU/Domain 不能为空")
		}
		prepared.IMSIdentity = IMSIdentityResolution{
			RequestedSource:  IMSIdentitySourceISIM,
			ActualSource:     IMSIdentitySourceISIM,
			AKAAppPreference: akaPreference,
			Applied:          true,
			IMPI:             strings.TrimSpace(id.IMPI),
			IMPU:             strings.TrimSpace(id.IMPU[0]),
			Domain:           strings.TrimSpace(id.Domain),
		}
	}
	if !prepared.IMSIdentity.Applied {
		domain := strings.TrimSpace(carrierCfg.Parameters.IMSDomain)
		if domain == "" {
			domain = defaultIMSDomain(profile)
		}
		actualSource := strings.TrimSpace(carrierCfg.ActualSource)
		if actualSource == "" {
			actualSource = IMSIdentitySourceGenerated
		}
		prepared.IMSIdentity = IMSIdentityResolution{
			RequestedSource:  requestedSource,
			ActualSource:     actualSource,
			AKAAppPreference: akaPreference,
			Applied:          false,
			IMPI:             profile.IMSI + "@" + domain,
			IMPU:             "sip:" + profile.IMSI + "@" + domain,
			Domain:           domain,
		}
	}

	override := strings.TrimSpace(input.RuntimeEPDGOverride)
	if override != "" {
		prepared.EPDGAddr = override
		prepared.EPDGSource = "redirect"
	} else {
		prepared.EPDGAddr = strings.TrimSpace(carrierCfg.EPDGAddr)
		prepared.EPDGSource = strings.TrimSpace(carrierCfg.EPDGSource)
		if prepared.EPDGAddr == "" {
			prepared.EPDGAddr = defaultEPDG(profile)
		}
		if prepared.EPDGSource == "" {
			prepared.EPDGSource = "derived"
		}
	}
	prepared.EffectiveCarrier.EPDGAddr = prepared.EPDGAddr
	return prepared, nil
}

func ReadISIMIdentity(access logicalChannelAccess) (Identity, error) {
	if access == nil {
		return Identity{}, fmt.Errorf("ISIM identity reader unavailable")
	}

	aid := isimAIDPrefix
	if resolver, ok := access.(logicalChannelAIDResolver); ok {
		if resolved, _, err := resolver.ResolveLogicalChannelAID("isim", isimAIDPrefix); err == nil && strings.TrimSpace(resolved) != "" {
			aid = strings.TrimSpace(resolved)
		}
	}

	ch, err := access.OpenLogicalChannel(aid)
	if err != nil {
		return Identity{}, fmt.Errorf("打开 ISIM 逻辑通道失败: %w", err)
	}
	defer access.CloseLogicalChannel(ch)

	impi, err := readISIMTransparentString(access, ch, efIMPI)
	if err != nil {
		return Identity{}, err
	}
	domain, err := readISIMTransparentString(access, ch, efDOMAIN)
	if err != nil {
		return Identity{}, err
	}
	impu, err := readISIMIMPU(access, ch)
	if err != nil {
		return Identity{}, err
	}
	return Identity{IMPI: impi, IMPU: impu, Domain: domain}, nil
}

func readISIMTransparentString(access logicalChannelAccess, ch int, fid string) (string, error) {
	if err := selectEF(access, ch, fid); err != nil {
		return "", err
	}
	body, sw1, sw2, err := transmit(access, ch, "00B0000000")
	if err != nil {
		return "", fmt.Errorf("读取 ISIM EF%s 失败: %w", fid, err)
	}
	if sw1 != 0x90 || sw2 != 0x00 {
		return "", fmt.Errorf("读取 ISIM EF%s 失败: SW=%02X%02X", fid, sw1, sw2)
	}
	value := extractISIMString(body)
	if value == "" {
		return "", fmt.Errorf("读取 ISIM EF%s 为空", fid)
	}
	return value, nil
}

func readISIMIMPU(access logicalChannelAccess, ch int) ([]string, error) {
	if err := selectEF(access, ch, efIMPU); err != nil {
		return nil, err
	}
	var out []string
	for rec := 1; rec <= 8; rec++ {
		body, sw1, sw2, err := transmit(access, ch, fmt.Sprintf("00B2%02X0400", rec))
		if err != nil {
			return nil, fmt.Errorf("读取 ISIM IMPU record %d: %w", rec, err)
		}
		if sw1 == 0x6A && sw2 == 0x83 {
			break
		}
		if sw1 != 0x90 || sw2 != 0x00 {
			return nil, fmt.Errorf("读取 ISIM IMPU record %d: SW=%02X%02X", rec, sw1, sw2)
		}
		if value := extractISIMString(body); value != "" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		body, sw1, sw2, err := transmit(access, ch, "00B0000000")
		if err == nil && sw1 == 0x90 && sw2 == 0x00 {
			if value := extractISIMString(body); value != "" {
				out = append(out, value)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("读取 ISIM EF%s 为空", efIMPU)
	}
	return out, nil
}

func selectEF(access logicalChannelAccess, ch int, fid string) error {
	_, sw1, sw2, err := transmit(access, ch, "00A4000402"+fid)
	if err != nil {
		return fmt.Errorf("选择 ISIM EF%s 失败: %w", fid, err)
	}
	if sw1 != 0x90 || sw2 != 0x00 {
		return fmt.Errorf("选择 ISIM EF%s 失败: SW=%02X%02X", fid, sw1, sw2)
	}
	return nil
}

// transmit handles ISO 7816 response chaining with a bounded number of exchanges.
// Modem backends encode the logical channel in their APDU transport.
func transmit(access logicalChannelAccess, ch int, apdu string) ([]byte, byte, byte, error) {
	var result []byte
	for attempt := 0; attempt < 16; attempt++ {
		respHex, err := access.TransmitAPDU(ch, apdu)
		if err != nil {
			return nil, 0, 0, err
		}
		resp, err := hex.DecodeString(strings.TrimSpace(respHex))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("HEX 解码失败: %w", err)
		}
		if len(resp) < 2 {
			return nil, 0, 0, fmt.Errorf("APDU 响应过短: %d", len(resp))
		}
		sw1, sw2 := resp[len(resp)-2], resp[len(resp)-1]
		if sw1 == 0x6C {
			command, err := hex.DecodeString(apdu)
			if err != nil || len(command) < 4 {
				return nil, 0, 0, fmt.Errorf("invalid APDU for corrected Le")
			}
			switch {
			case len(command) == 4:
				command = append(command, sw2)
			case len(command) == 5:
				command[4] = sw2
			case command[4] > 0 && len(command) == 5+int(command[4]):
				command = append(command, sw2)
			case command[4] > 0 && len(command) == 6+int(command[4]):
				command[len(command)-1] = sw2
			default:
				return nil, 0, 0, fmt.Errorf("unsupported APDU for corrected Le")
			}
			apdu = strings.ToUpper(hex.EncodeToString(command))
			continue
		}
		result = append(result, resp[:len(resp)-2]...)
		if sw1 == 0x61 {
			// Le=00 requests 256 bytes, including SW=6100.
			apdu = fmt.Sprintf("00C00000%02X", sw2)
			continue
		}
		return result, sw1, sw2, nil
	}
	return nil, 0, 0, fmt.Errorf("APDU procedure exceeded 16 exchanges")
}

func extractISIMString(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if value := findTLVString(body, 0x80); value != "" {
		return value
	}
	// ISIM EFs encode identities in an 0x80 TLV (3GPP TS 31.103).
	// A truncated or absent TLV is not a usable raw identity.
	return ""
}

func findTLVString(body []byte, want byte) string {
	for i := 0; i+2 <= len(body); {
		tag := body[i]
		i++
		if i >= len(body) {
			break
		}
		length := int(body[i])
		i++
		if length&0x80 != 0 {
			n := length & 0x7f
			if n == 0 || n > 2 || i+n > len(body) {
				break
			}
			length = 0
			for j := 0; j < n; j++ {
				length = length<<8 | int(body[i+j])
			}
			i += n
		}
		if length < 0 || i+length > len(body) {
			break
		}
		if tag == want {
			if s := cleanISIMString(body[i : i+length]); validIdentityText(s) {
				return s
			}
		}
		i += length
	}
	return ""
}

func cleanISIMString(raw []byte) string {
	start, end := 0, len(raw)
	for start < end && (raw[start] == 0x00 || raw[start] == 0xff) {
		start++
	}
	for end > start && (raw[end-1] == 0x00 || raw[end-1] == 0xff) {
		end--
	}
	return strings.TrimSpace(string(raw[start:end]))
}

func completeIdentity(id Identity) bool {
	if !validIdentityText(id.IMPI) || !validIdentityText(id.Domain) || len(id.IMPU) == 0 {
		return false
	}
	return validIdentityText(id.IMPU[0])
}

func validIdentityText(s string) bool {
	if strings.TrimSpace(s) == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func defaultIMSDomain(p Profile) string {
	if p.MCC == "310" && p.MNC == "280" {
		return "one.att.net"
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", padMNC(p.MNC), p.MCC)
}

func defaultEPDG(p Profile) string {
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", padMNC(p.MNC), p.MCC)
}

func padMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}
