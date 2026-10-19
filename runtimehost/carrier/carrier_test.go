package carrier

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeOverrides(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "carriers.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestOverridesNormalizeMNCWithoutDroppingZero(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	for _, mnc := range []string{"00", "01", "024"} {
		path := writeOverrides(t, fmt.Sprintf(`{"530/%s":{"epdg_addr":"override.example"}}`, mnc))
		res, err := LoadCarrierOverrides(path)
		if err != nil {
			t.Fatal(err)
		}
		if res.Count != 1 {
			t.Fatalf("normalized count %d", res.Count)
		}
		if c := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "530", MNC: mnc}); c.EPDGAddr != "override.example" {
			t.Fatalf("lost zero-prefixed carrier %+v", c)
		}
	}
}
func TestInvalidOverridesLeaveCurrentSnapshotUntouched(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	if _, err := LoadCarrierOverrides(writeOverrides(t, `[{"mcc":"530","mnc":"24","epdg_addr":"keep.example"}]`)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`[{"mcc":"530","mnc":"24"},{"mcc":"530","mnc":"024"}]`,
		`[{"mcc":"53x","mnc":"24"}]`,
		`{"invalid":{"epdg_addr":"bad.example"}}`,
	} {
		if _, err := LoadCarrierOverrides(writeOverrides(t, body)); err == nil {
			t.Fatalf("invalid override accepted: %s", body)
		}
		if c := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "530", MNC: "24"}); c.EPDGAddr != "keep.example" {
			t.Fatalf("invalid load replaced active snapshot %+v", c)
		}
	}
}

func TestRecoveredPresetsAndDefaults(t *testing.T) {
	if len(builtinConfigs) != 16 {
		t.Fatalf("preset count %d", len(builtinConfigs))
	}
	c := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "530", MNC: "24"})
	if c.EPDGAddr != "epdg.ims.2degrees.net.nz" || c.EPDGSource != "preset" || c.Parameters.IKEProposals[0] != "aes256-sha512-prfsha512-modp1024" {
		t.Fatalf("2degrees preset lost %+v", c)
	}
	if c.Parameters.APN != "ims" || c.Parameters.EPDGPort != 500 || c.Parameters.NATKeepaliveSeconds != 20 {
		t.Fatalf("defaults not overlaid %+v", c.Parameters)
	}
	att := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "410"})
	if att.RequestedSource != "isim" || att.AKAAppPreference != "isim_strict" || att.E911.Provider != "att_entitlement" {
		t.Fatalf("AT&T alias %+v", att)
	}
	if !*att.Parameters.IMSRegisterTemplate.StrictSecurityServerOffer || len(att.Parameters.IMSRegisterTemplate.SecurityClientMechanisms) != 1 {
		t.Fatal("ATT registration policy lost")
	}
	for _, mcc := range []string{"460", "461", " 460 ", "0461"} {
		if !IsVoWiFiBlockedMCC(mcc) {
			t.Errorf("blocked MCC %q allowed", mcc)
		}
	}
	for _, mcc := range []string{"462", "460x", "-460"} {
		if IsVoWiFiBlockedMCC(mcc) {
			t.Errorf("unblocked MCC %q denied", mcc)
		}
	}
}
func TestResolvedConfigOwnsMutableValues(t *testing.T) {
	input := EffectiveCarrierConfigInput{MCC: "310", MNC: "280"}
	c := ResolveEffectiveCarrierConfig(input)
	c.Parameters.IKEProposals[0] = "bad"
	*c.Parameters.IMSRegisterTemplate.IncludePANIAuthenticated = false
	c.Parameters.IMSRegisterTemplate.RegisterPolicy.TemporaryStatusCodes[0] = 999
	next := ResolveEffectiveCarrierConfig(input)
	if next.Parameters.IKEProposals[0] == "bad" || !*next.Parameters.IMSRegisterTemplate.IncludePANIAuthenticated || next.Parameters.IMSRegisterTemplate.RegisterPolicy.TemporaryStatusCodes[0] == 999 {
		t.Fatal("caller modified global carrier preset")
	}
}

func TestOverrideDoesNotEraseStrictIdentityPolicy(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	if _, err := LoadCarrierOverrides(writeOverrides(t, `{"310/280":{"epdg_addr":"override.example"}}`)); err != nil {
		t.Fatal(err)
	}
	c := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	if c.EPDGAddr != "override.example" || c.RequestedSource != "isim" || c.AKAAppPreference != "isim_strict" || !*c.Parameters.IMSRegisterTemplate.StrictSecurityServerOffer {
		t.Fatalf("override erased carrier authentication policy: %+v", c)
	}
}

func TestNestedOverrideRetainsDefaultsAndExplicitFalse(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	body := `{"310/280":{"e911":{"enabled":false},"parameters":{"ims_register_template":{"strict_security_server_offer":false,"register_policy":{"temporary_retry_seconds":17,"forbidden_status_codes":[]}}}}}`
	if _, err := LoadCarrierOverrides(writeOverrides(t, body)); err != nil {
		t.Fatal(err)
	}
	c := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	r := c.Parameters.IMSRegisterTemplate
	if c.E911.Enabled || c.E911.Provider != "att_entitlement" || *r.StrictSecurityServerOffer || r.Expires != 600000 || len(r.SecurityClientMechanisms) != 1 || r.RegisterPolicy.TemporaryRetrySeconds != 17 || len(r.RegisterPolicy.TemporaryStatusCodes) != 5 || len(r.RegisterPolicy.ForbiddenStatusCodes) != 0 {
		t.Fatalf("partial nested merge lost presence semantics: %+v %+v", c.E911, r)
	}
}
