package carrier

// globalDefaultParameters reproduces GetGlobalDefaultConfig values recovered
// from the target binary. See presets/PROVENANCE.md and defaults-evidence.json.
// Supported protocol algorithms are checked separately by runtime engines.
func globalDefaultParameters() PresetParameters {
	return PresetParameters{
		EPDGPort: 500, APN: "ims", IPStack: "ipv4v6", NATKeepaliveSeconds: 20, DPDIntervalSeconds: 120,
		AKAChallengeMode: "minimal", IKEIdentityMode: "epc_nai", AKAIdentityMode: "epc_nai",
		DeviceIdentityEnabled: boolPointer(false), DeviceModel: "iphone15,4",
		IMSIdentitySource: "derived", IMSTransport: "auto", IMSLocalPort: 5060,
		IMSTCPKeepaliveSeconds: 30, IMSOptionsPingIntervalSeconds: 45,
		IKEProposals: []string{"aes128-sha256-modp2048", "aes128-sha256-modp1024", "aes128-sha1-modp1024", "aes256-sha1-modp1024"},
		ESPProposals: []string{"aes256gcm16", "aes128gcm16", "aes128-sha256", "aes128-sha1"},
		IMSRegisterTemplate: RegisterTemplate{
			ID: "defaultIMSRegisterTemplate", UsePlainDigestPlaceholder: boolPointer(true), Expires: 600000,
			SMSReceiverTransport: "dual", ContactMode: "android_default", SupportedHeader: "path,sec-agree",
			AllowHeader: "OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, REFER, INFO, MESSAGE",
			AccessType:  "wlan1", ICSIReference: "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.sms",
			ContactParamOrder:      []string{"access_type", "sip_instance", "audio", "smsip", "icsi_ref"},
			VoiceSupportedHeader:   "100rel, timer, replaces, norefersub, early-session",
			VoiceAllowHeader:       "INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, OPTIONS",
			VoiceAcceptContact:     `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
			VoicePPreferredService: "urn:urn-7:3gpp-service.ims.icsi.mmtel",
			ForceHeaderPort5060:    boolPointer(false), IncludePANIAuthenticated: boolPointer(true),
			IncludeConnectionKeepaliveInAuth: boolPointer(false), SecAgreeMode: "auto",
			SecurityClientIncludesServerParams: boolPointer(true),
			SecurityClientMechanisms: []SecurityMechanism{
				{Algorithm: "hmac-md5-96", EncryptionAlgorithm: "des-ede3-cbc", Protocol: "esp", Mode: "trans"},
				{Algorithm: "hmac-md5-96", EncryptionAlgorithm: "aes-cbc", Protocol: "esp", Mode: "trans"},
				{Algorithm: "hmac-md5-96", EncryptionAlgorithm: "null", Protocol: "esp", Mode: "trans"},
				{Algorithm: "hmac-sha-1-96", EncryptionAlgorithm: "des-ede3-cbc", Protocol: "esp", Mode: "trans"},
				{Algorithm: "hmac-sha-1-96", EncryptionAlgorithm: "aes-cbc", Protocol: "esp", Mode: "trans"},
				{Algorithm: "hmac-sha-1-96", EncryptionAlgorithm: "null", Protocol: "esp", Mode: "trans"},
			},
			StrictSecurityServerOffer: boolPointer(false), EnableInitialRejectFallback: boolPointer(true),
			FallbackIncludesServerParamsInSecCl: boolPointer(false),
			RegisterPolicy:                      RegisterPolicy{ID: "default", TemporaryStatusCodes: []int{408, 429, 500, 502, 503, 504}, ForbiddenStatusCodes: []int{403}, InitialRejectFallbackStatusCodes: []int{400, 403, 500}, TemporaryRetrySeconds: 60},
		},
	}
}

func boolPointer(v bool) *bool { return &v }

func cloneConfig(cfg EffectiveCarrierConfig) EffectiveCarrierConfig {
	p := &cfg.Parameters
	p.IKEProposals = append([]string(nil), p.IKEProposals...)
	p.ESPProposals = append([]string(nil), p.ESPProposals...)
	p.AllowedLegacyCiphers = append([]string(nil), p.AllowedLegacyCiphers...)
	p.DeviceIdentityEnabled = cloneBool(p.DeviceIdentityEnabled)
	r := &p.IMSRegisterTemplate
	r.IncludePANIAuthenticated = cloneBool(r.IncludePANIAuthenticated)
	r.StrictSecurityServerOffer = cloneBool(r.StrictSecurityServerOffer)
	r.EnableInitialRejectFallback = cloneBool(r.EnableInitialRejectFallback)
	r.UsePlainDigestPlaceholder = cloneBool(r.UsePlainDigestPlaceholder)
	r.ForceHeaderPort5060 = cloneBool(r.ForceHeaderPort5060)
	r.IncludeConnectionKeepaliveInAuth = cloneBool(r.IncludeConnectionKeepaliveInAuth)
	r.SecurityClientIncludesServerParams = cloneBool(r.SecurityClientIncludesServerParams)
	r.FallbackIncludesServerParamsInSecCl = cloneBool(r.FallbackIncludesServerParamsInSecCl)
	r.SecurityClientMechanisms = append([]SecurityMechanism(nil), r.SecurityClientMechanisms...)
	r.ContactParamOrder = append([]string(nil), r.ContactParamOrder...)
	r.RegisterPolicy.TemporaryStatusCodes = append([]int(nil), r.RegisterPolicy.TemporaryStatusCodes...)
	r.RegisterPolicy.ForbiddenStatusCodes = append([]int(nil), r.RegisterPolicy.ForbiddenStatusCodes...)
	r.RegisterPolicy.InitialRejectFallbackStatusCodes = append([]int(nil), r.RegisterPolicy.InitialRejectFallbackStatusCodes...)
	return cfg
}
func cloneBool(v *bool) *bool {
	if v == nil {
		return nil
	}
	return boolPointer(*v)
}
