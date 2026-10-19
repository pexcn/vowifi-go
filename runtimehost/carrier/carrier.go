package carrier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type E911Config struct {
	Enabled            bool   `json:"enabled" yaml:"enabled"`
	Provider           string `json:"provider" yaml:"provider"`
	EntitlementURL     string `json:"entitlement_url" yaml:"entitlement_url"`
	WebsheetHostPolicy string `json:"websheet_host_policy" yaml:"websheet_host_policy"`
	WebsheetURL        string `json:"websheet_url" yaml:"websheet_url"`
	Title              string `json:"title" yaml:"title"`
	ContentType        string `json:"content_type" yaml:"content_type"`
	UserData           string `json:"user_data" yaml:"user_data"`
}

type EffectiveCarrierConfig struct {
	// Parameters preserve recovered preset values; omitted option flags remain nil.
	Parameters       PresetParameters `json:"parameters" yaml:"parameters"`
	MCC              string           `json:"mcc" yaml:"mcc"`
	MNC              string           `json:"mnc" yaml:"mnc"`
	PresetID         string           `json:"preset_id" yaml:"preset_id"`
	EPDGAddr         string           `json:"epdg_addr" yaml:"epdg_addr"`
	EPDGSource       string           `json:"epdg_source" yaml:"epdg_source"`
	IdentitySource   string           `json:"identity_source" yaml:"identity_source"`
	RequestedSource  string           `json:"requested_source" yaml:"requested_source"`
	ActualSource     string           `json:"actual_source" yaml:"actual_source"`
	AKAAppPreference string           `json:"aka_app_preference" yaml:"aka_app_preference"`
	RegisterTemplate string           `json:"register_template" yaml:"register_template"`
	RegisterPolicy   string           `json:"register_policy" yaml:"register_policy"`
	E911             E911Config       `json:"e911" yaml:"e911"`
}

type EffectiveCarrierConfigInput struct {
	MCC string
	MNC string
}

type CarrierOverridesLoadResult struct {
	Path    string
	Missing bool
	Count   int
}

type VoWiFiBlockedMCCError struct {
	MCC string
}

func (e VoWiFiBlockedMCCError) Error() string {
	return fmt.Sprintf("VoWiFi is blocked by carrier policy for MCC %s", e.MCC)
}

var (
	overridesMu sync.RWMutex
	overrides   map[string]EffectiveCarrierConfig
)

var builtinConfigs = loadBuiltinConfigs()

func LoadCarrierOverrides(path string) (CarrierOverridesLoadResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = filepath.Join("config", "carrier_overrides.json")
	}
	res := CarrierOverridesLoadResult{Path: path}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Missing = true
			return res, nil
		}
		return res, err
	}
	var raw map[string]json.RawMessage
	var list []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		if errList := json.Unmarshal(body, &list); errList != nil {
			return res, err
		}
	} else {
		for k, entry := range raw {
			var cfg EffectiveCarrierConfig
			if err := json.Unmarshal(entry, &cfg); err != nil {
				return res, err
			}
			if cfg.MCC == "" || cfg.MNC == "" {
				parts := strings.Split(k, "/")
				if len(parts) != 2 {
					return res, fmt.Errorf("invalid carrier key %q", k)
				}
				cfg.MCC, cfg.MNC = parts[0], parts[1]
			}
			entryMap := map[string]json.RawMessage{}
			if err := json.Unmarshal(entry, &entryMap); err != nil {
				return res, err
			}
			entryMap["mcc"], _ = json.Marshal(cfg.MCC)
			entryMap["mnc"], _ = json.Marshal(cfg.MNC)
			encoded, err := json.Marshal(entryMap)
			if err != nil {
				return res, err
			}
			list = append(list, encoded)
		}
	}
	parsed := make(map[string]EffectiveCarrierConfig, len(list))
	for _, entry := range list {
		var cfg EffectiveCarrierConfig
		if err := json.Unmarshal(entry, &cfg); err != nil {
			return res, err
		}
		cfg.MCC, cfg.MNC = strings.TrimSpace(cfg.MCC), strings.TrimSpace(cfg.MNC)
		if !validDigits(cfg.MCC, 3, 3) || !validDigits(cfg.MNC, 2, 3) {
			return res, fmt.Errorf("invalid carrier PLMN %q/%q", cfg.MCC, cfg.MNC)
		}
		k := key(cfg.MCC, cfg.MNC)
		if _, exists := parsed[k]; exists {
			return res, fmt.Errorf("duplicate carrier PLMN %q", k)
		}
		base, ok := builtinConfigs[k]
		if !ok {
			base = EffectiveCarrierConfig{MCC: cfg.MCC, MNC: cfg.MNC, Parameters: globalDefaultParameters()}
		}
		base = cloneConfig(base)
		if err := json.Unmarshal(entry, &base); err != nil {
			return res, err
		}
		parsed[k] = normalizeConfig(base)
	}

	overridesMu.Lock()
	overrides = parsed
	overridesMu.Unlock()
	res.Count = len(parsed)
	return res, nil
}

func ClearCarrierOverrides() {
	overridesMu.Lock()
	overrides = nil
	overridesMu.Unlock()
}

func ResolveEffectiveCarrierConfig(input EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	mcc, mnc := strings.TrimSpace(input.MCC), strings.TrimSpace(input.MNC)
	k := key(mcc, mnc)
	overridesMu.RLock()
	if cfg, ok := overrides[k]; ok {
		overridesMu.RUnlock()
		return normalizeConfig(cfg)
	}
	overridesMu.RUnlock()
	if cfg, ok := builtinConfigs[k]; ok {
		return normalizeConfig(cfg)
	}
	return normalizeConfig(EffectiveCarrierConfig{MCC: mcc, MNC: mnc, Parameters: globalDefaultParameters()})
}

func IsVoWiFiBlockedMCC(mcc string) bool {
	switch plmn3(mcc) {
	case "460", "461":
		return true
	default:
		return false
	}
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return VoWiFiBlockedMCCError{MCC: strings.TrimSpace(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	var blockErr VoWiFiBlockedMCCError
	return errors.As(err, &blockErr)
}

func normalizeConfig(cfg EffectiveCarrierConfig) EffectiveCarrierConfig {
	cfg.MCC = strings.TrimSpace(cfg.MCC)
	cfg.MNC = strings.TrimSpace(cfg.MNC)
	if cfg.PresetID == "" && (cfg.MCC != "" || cfg.MNC != "") {
		cfg.PresetID = cfg.MCC + "/" + padMNC(cfg.MNC)
	}
	if cfg.EPDGAddr == "" && cfg.MCC != "" && cfg.MNC != "" {
		cfg.EPDGAddr = fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", padMNC(cfg.MNC), cfg.MCC)
	}
	if cfg.EPDGSource == "" {
		cfg.EPDGSource = "standard"
	}
	if cfg.IdentitySource == "" {
		cfg.IdentitySource = "profile"
	}
	if cfg.RequestedSource == "" {
		cfg.RequestedSource = "derived"
	}
	if cfg.ActualSource == "" {
		cfg.ActualSource = cfg.RequestedSource
	}
	if cfg.AKAAppPreference == "" {
		cfg.AKAAppPreference = "usim"
	}
	if cfg.RegisterTemplate == "" {
		cfg.RegisterTemplate = cfg.PresetID
	}
	if cfg.RegisterPolicy == "" {
		cfg.RegisterPolicy = "default"
	}
	if cfg.E911.ContentType == "" {
		cfg.E911.ContentType = "text/html"
	}
	if cfg.E911.Title == "" {
		cfg.E911.Title = "Emergency Address"
	}
	if cfg.Parameters.IMSDomain == "" && cfg.MCC != "" && cfg.MNC != "" {
		cfg.Parameters.IMSDomain = fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", plmn3(cfg.MNC), plmn3(cfg.MCC))
	}
	if cfg.Parameters.IMSRealm == "" {
		cfg.Parameters.IMSRealm = cfg.Parameters.IMSDomain
	}
	return cloneConfig(cfg)
}

// plmn3 reproduces the binary's common.Plmn3 normalization for numeric PLMN
// components while retaining nonnumeric input for later validation.
func plmn3(s string) string {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 999 {
		return fmt.Sprintf("%03d", n)
	}
	return s
}

func key(mcc, mnc string) string { return plmn3(mcc) + plmn3(mnc) }

func padMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}

func validDigits(s string, min, max int) bool {
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
