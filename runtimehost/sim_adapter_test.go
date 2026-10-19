package runtimehost

import (
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

type selectionProvider struct {
	usim, isim int
	err        error
}

func (p *selectionProvider) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	p.usim++
	return sim.AKAResult{RES: []byte("usim")}, nil
}
func (p *selectionProvider) CalculateISIMAKA([]byte, []byte) (sim.AKAResult, error) {
	p.isim++
	return sim.AKAResult{RES: []byte("isim")}, p.err
}
func TestReaderAdapterPreservesStrictISIMForEAPAndIMS(t *testing.T) {
	p := &selectionProvider{}
	adapter := NewReaderSIMAdapter(p)
	for _, provider := range []sim.AKAProvider{adapter, selectedSIM{provider: adapter, preference: "isim_strict"}} {
		var result sim.AKAResult
		var err error
		if pref, ok := provider.(sim.AKAWithPreferenceProvider); ok {
			result, err = pref.CalculateAKAWithPreference(nil, nil, "isim_strict")
		} else {
			result, err = provider.CalculateAKA(nil, nil)
		}
		if err != nil || string(result.RES) != "isim" {
			t.Fatalf("strict selection lost %q %v", result.RES, err)
		}
	}
	if p.usim != 0 || p.isim != 2 {
		t.Fatalf("unexpected SIM application: %+v", p)
	}
	p.err = errors.New("ISIM failed")
	if _, err := adapter.(sim.AKAWithPreferenceProvider).CalculateAKAWithPreference(nil, nil, "isim_strict"); !errors.Is(err, p.err) {
		t.Fatal(err)
	}
	if p.usim != 0 {
		t.Fatal("strict failure fell back to USIM")
	}
}
func TestStrictISIMRejectsGenericProvider(t *testing.T) {
	adapter := NewReaderSIMAdapter(testSIM{})
	if _, err := adapter.(sim.AKAWithPreferenceProvider).CalculateAKAWithPreference(nil, nil, "isim_strict"); err == nil {
		t.Fatal("missing strict provider silently accepted")
	}
}
