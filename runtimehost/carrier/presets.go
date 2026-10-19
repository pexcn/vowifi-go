package carrier

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed presets/*.yaml
var presetFiles embed.FS

// PresetParameters are verbatim per-carrier settings recovered from the shipped
// binary. A nil option flag means that the preset did not specify that flag.
// Runtime consumers must resolve their own documented defaults.
type PresetParameters struct {
	EPDGPort                      int      `json:"epdg_port" yaml:"epdg_port"`
	DNSServer                     string   `json:"dns_server" yaml:"dns_server"`
	IKEIdentityMode               string   `json:"ike_identity_mode" yaml:"ike_identity_mode"`
	AKAIdentityMode               string   `json:"aka_identity_mode" yaml:"aka_identity_mode"`
	EnableLegacyCiphers           bool     `json:"enable_legacy_ciphers" yaml:"enable_legacy_ciphers"`
	AllowedLegacyCiphers          []string `json:"allowed_legacy_ciphers" yaml:"allowed_legacy_ciphers"`
	AlgorithmPolicy               string   `json:"algorithm_policy" yaml:"algorithm_policy"`
	DeviceIdentityIMEI            string   `json:"device_identity_imei" yaml:"device_identity_imei"`
	IMSRegistrar                  string   `json:"ims_registrar" yaml:"ims_registrar"`
	IMSPCSCF                      string   `json:"ims_pcscf" yaml:"ims_pcscf"`
	IMSUserAgent                  string   `json:"ims_user_agent" yaml:"ims_user_agent"`
	IMSTransport                  string   `json:"ims_transport" yaml:"ims_transport"`
	IMSLocalPort                  int      `json:"ims_local_port" yaml:"ims_local_port"`
	IMSTCPKeepaliveSeconds        int      `json:"ims_tcp_keepalive_seconds" yaml:"ims_tcp_keepalive_seconds"`
	IMSOptionsPingIntervalSeconds int      `json:"ims_options_ping_interval_seconds" yaml:"ims_options_ping_interval_seconds"`
	DPDKeepaliveIntervalSeconds   int      `json:"dpd_keepalive_interval_seconds" yaml:"dpd_keepalive_interval_seconds"`
	SMSRoutingMethod              string   `json:"sms_routing_method" yaml:"sms_routing_method"`
	SMSRoutingGW                  string   `json:"sms_routing_gw" yaml:"sms_routing_gw"`
	ForceSMSCAuth                 bool     `json:"force_smsc_auth" yaml:"force_smsc_auth"`

	CustomEPDG            string           `json:"custom_epdg" yaml:"custom_epdg"`
	APN                   string           `json:"apn" yaml:"apn"`
	IPStack               string           `json:"ip_stack" yaml:"ip_stack"`
	AKAChallengeMode      string           `json:"aka_challenge_mode" yaml:"aka_challenge_mode"`
	DeviceModel           string           `json:"device_model" yaml:"device_model"`
	DeviceIdentityEnabled *bool            `json:"device_identity_enabled,omitempty" yaml:"device_identity_enabled"`
	IMSIdentitySource     string           `json:"ims_identity_source" yaml:"ims_identity_source"`
	IMSDomain             string           `json:"ims_domain" yaml:"ims_domain"`
	IMSRealm              string           `json:"ims_realm" yaml:"ims_realm"`
	NATKeepaliveSeconds   int              `json:"nat_keepalive_seconds" yaml:"nat_keepalive_seconds"`
	DPDIntervalSeconds    int              `json:"dpd_interval_seconds" yaml:"dpd_interval_seconds"`
	ReauthIntervalSeconds int              `json:"reauth_interval_seconds" yaml:"reauth_interval_seconds"`
	IKEProposals          []string         `json:"ike_proposals" yaml:"ike_proposals"`
	ESPProposals          []string         `json:"esp_proposals" yaml:"esp_proposals"`
	IMSRegisterTemplate   RegisterTemplate `json:"ims_register_template" yaml:"ims_register_template"`
}

type SecurityMechanism struct {
	Algorithm           string `json:"alg" yaml:"alg"`
	EncryptionAlgorithm string `json:"ealg" yaml:"ealg"`
	Protocol            string `json:"prot" yaml:"prot"`
	Mode                string `json:"mode" yaml:"mode"`
}

type RegisterTemplate struct {
	Expires                             int    `json:"expires" yaml:"expires"`
	SMSReceiverTransport                string `json:"sms_receiver_transport" yaml:"sms_receiver_transport"`
	ContactMode                         string `json:"contact_mode" yaml:"contact_mode"`
	FixedPANI                           string `json:"fixed_pani" yaml:"fixed_pani"`
	AccessType                          string `json:"access_type" yaml:"access_type"`
	VoiceSupportedHeader                string `json:"voice_supported_header" yaml:"voice_supported_header"`
	VoiceAllowHeader                    string `json:"voice_allow_header" yaml:"voice_allow_header"`
	VoiceAcceptContact                  string `json:"voice_accept_contact" yaml:"voice_accept_contact"`
	VoicePPreferredService              string `json:"voice_p_preferred_service" yaml:"voice_p_preferred_service"`
	ForceHeaderPort5060                 *bool  `json:"force_header_port_5060,omitempty" yaml:"force_header_port_5060"`
	IncludeConnectionKeepaliveInAuth    *bool  `json:"include_connection_keepalive_in_auth,omitempty" yaml:"include_connection_keepalive_in_auth"`
	SecurityClientIncludesServerParams  *bool  `json:"security_client_includes_server_params,omitempty" yaml:"security_client_includes_server_params"`
	FallbackIncludesServerParamsInSecCl *bool  `json:"fallback_includes_server_params_in_sec_cl,omitempty" yaml:"fallback_includes_server_params_in_sec_cl"`

	ID                          string              `json:"id" yaml:"id"`
	SupportedHeader             string              `json:"supported_header" yaml:"supported_header"`
	AllowHeader                 string              `json:"allow_header" yaml:"allow_header"`
	ICSIReference               string              `json:"icsi_ref" yaml:"icsi_ref"`
	SecAgreeMode                string              `json:"sec_agree_mode" yaml:"sec_agree_mode"`
	IncludePANIAuthenticated    *bool               `json:"include_pani_authenticated,omitempty" yaml:"include_pani_authenticated"`
	StrictSecurityServerOffer   *bool               `json:"strict_security_server_offer,omitempty" yaml:"strict_security_server_offer"`
	EnableInitialRejectFallback *bool               `json:"enable_initial_reject_fallback,omitempty" yaml:"enable_initial_reject_fallback"`
	UsePlainDigestPlaceholder   *bool               `json:"use_plain_digest_placeholder,omitempty" yaml:"use_plain_digest_placeholder"`
	SecurityClientMechanisms    []SecurityMechanism `json:"security_client_mechanisms" yaml:"security_client_mechanisms"`
	ContactParamOrder           []string            `json:"contact_param_order" yaml:"contact_param_order"`
	RegisterPolicy              RegisterPolicy      `json:"register_policy" yaml:"register_policy"`
}

type RegisterPolicy struct {
	ID                               string `json:"id" yaml:"id"`
	TemporaryStatusCodes             []int  `json:"temporary_status_codes" yaml:"temporary_status_codes"`
	ForbiddenStatusCodes             []int  `json:"forbidden_status_codes" yaml:"forbidden_status_codes"`
	InitialRejectFallbackStatusCodes []int  `json:"initial_reject_fallback_status_codes" yaml:"initial_reject_fallback_status_codes"`
	TemporaryRetrySeconds            int    `json:"temporary_retry_seconds" yaml:"temporary_retry_seconds"`
}

type embeddedPreset struct {
	MCC              string     `yaml:"mcc"`
	MNC              string     `yaml:"mnc"`
	ID               string     `yaml:"id"`
	E911             E911Config `yaml:"e911"`
	PresetParameters `yaml:",inline"`
}

func loadBuiltinConfigs() map[string]EffectiveCarrierConfig {
	entries, err := fs.Glob(presetFiles, "presets/*.yaml")
	if err != nil {
		panic(err)
	}
	out := make(map[string]EffectiveCarrierConfig, len(entries))
	for _, name := range entries {
		body, err := presetFiles.ReadFile(name)
		if err != nil {
			panic(err)
		}
		p := embeddedPreset{PresetParameters: globalDefaultParameters()}
		decoder := yaml.NewDecoder(strings.NewReader(string(body)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&p); err != nil {
			panic(fmt.Errorf("embedded carrier preset %s: %w", name, err))
		}
		cfg := EffectiveCarrierConfig{MCC: p.MCC, MNC: p.MNC, PresetID: p.ID, Parameters: p.PresetParameters, E911: p.E911, EPDGAddr: p.CustomEPDG}
		if cfg.EPDGAddr != "" {
			cfg.EPDGSource = "preset"
		}
		if p.IMSIdentitySource != "" {
			cfg.RequestedSource = p.IMSIdentitySource
			cfg.ActualSource = p.IMSIdentitySource
			if p.IMSIdentitySource == "isim" {
				cfg.AKAAppPreference = "isim_strict"
			}
		}
		cfg.RegisterTemplate = p.IMSRegisterTemplate.ID
		cfg.RegisterPolicy = p.IMSRegisterTemplate.RegisterPolicy.ID
		if p.DeviceModel != "" {
			cfg.IdentitySource = "carrier_device_model"
		}
		if _, exists := out[key(p.MCC, p.MNC)]; exists {
			panic("duplicate embedded carrier PLMN")
		}
		out[key(p.MCC, p.MNC)] = cfg
	}
	return out
}
