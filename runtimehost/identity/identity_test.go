package identity

import (
	"errors"
	"strings"
	"testing"
)

type identityReader struct {
	identity Identity
	err      error
}

func (r identityReader) GetISIMIdentity() (Identity, error) { return r.identity, r.err }

func TestStrictISIMNeverFallsBack(t *testing.T) {
	p := Profile{IMSI: "310280000000001", MCC: "310", MNC: "280"}
	cause := errors.New("logical channel busy")
	for _, tc := range []struct {
		name   string
		reader interface{ GetISIMIdentity() (Identity, error) }
		want   error
	}{
		{name: "missing"},
		{name: "failure", reader: identityReader{err: cause}, want: cause},
		{name: "incomplete", reader: identityReader{identity: Identity{IMPI: "user@private.att.net"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PrepareStart(PrepareStartInput{Profile: p, Access: tc.reader})
			if err == nil {
				t.Fatal("strict ISIM must fail instead of generating identities")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error chain lost: %v", err)
			}
		})
	}
}

func TestPreparedISIMAndRuntimeRedirect(t *testing.T) {
	p, err := PrepareStart(PrepareStartInput{Profile: Profile{IMSI: "310280000000001", MCC: "310", MNC: "280"}, RuntimeEPDGOverride: "epdg.example", Access: identityReader{identity: Identity{IMPI: "user@private.att.net", IMPU: []string{"sip:user@one.att.net"}, Domain: "one.att.net"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IMSIdentity.Applied || p.IMSIdentity.ActualSource != IMSIdentitySourceISIM || p.IMSIdentity.AKAAppPreference != AKAAppPreferenceISIMStrict {
		t.Fatalf("identity resolution: %+v", p.IMSIdentity)
	}
	if p.EPDGAddr != "epdg.example" || p.EPDGSource != "redirect" {
		t.Fatalf("redirect lost: %+v", p)
	}
}

func TestNormalizeDoesNotGuessMNCLength(t *testing.T) {
	if p := NormalizeProfile(Profile{IMSI: "530240000000001"}); p.MNC != "" {
		t.Fatalf("ambiguous MNC inferred: %+v", p)
	}
	p, err := PrepareStart(PrepareStartInput{Profile: Profile{IMSI: "530240000000001", MCC: "530", MNC: "24"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile.MNC != "24" || p.IMSIdentity.Domain != "ims.mnc024.mcc530.3gppnetwork.org" {
		t.Fatalf("MNC normalization: %+v", p)
	}
}

type apduFake struct {
	responses []string
	commands  []string
	err       error
}

func (f *apduFake) OpenLogicalChannel(string) (int, error) { return 1, nil }
func (f *apduFake) CloseLogicalChannel(int) error          { return nil }
func (f *apduFake) TransmitAPDU(_ int, c string) (string, error) {
	f.commands = append(f.commands, c)
	if f.err != nil {
		return "", f.err
	}
	if len(f.responses) == 0 {
		return "6100", nil
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return r, nil
}

func TestAPDUProceduresPreserveChainedData(t *testing.T) {
	f := &apduFake{responses: []string{"6C03", "80036100", "6162639000"}}
	b, sw1, sw2, err := transmit(f, 1, "00B0000000")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string([]byte{0x80, 0x03, 'a', 'b', 'c'}) || sw1 != 0x90 || sw2 != 0 {
		t.Fatalf("result %x SW=%02x%02x", b, sw1, sw2)
	}
	if got := strings.Join(f.commands, ","); got != "00B0000000,00B0000003,00C0000000" {
		t.Fatalf("commands: %s", got)
	}
}
func TestAPDUProceduresAreBounded(t *testing.T) {
	f := &apduFake{}
	if _, _, _, err := transmit(f, 1, "00B0000000"); err == nil {
		t.Fatal("unbounded procedure accepted")
	}
	if len(f.commands) != 16 {
		t.Fatalf("exchange limit: %d", len(f.commands))
	}
}
func TestTransparentReadRejectsErrorStatusWithPlausibleBody(t *testing.T) {
	f := &apduFake{responses: []string{"9000", "80036162636982"}}
	if _, err := readISIMTransparentString(f, 1, efIMPI); err == nil {
		t.Fatal("READ with SW=6982 must not yield identity")
	}
}

func TestISIMRejectsMalformedTLVAndControlCharacters(t *testing.T) {
	for _, body := range [][]byte{{0x80, 5, 'a', 'b'}, []byte("user@example.org"), {0x80, 2, 0xff, 0x81}, {0x80, 4, 'a', '\r', '\n', 'b'}} {
		if got := extractISIMString(body); got != "" {
			t.Errorf("invalid EF yielded identity %q", got)
		}
	}
	if got := extractISIMString([]byte{0x80, 3, 'a', 'b', 'c', 0xff, 0xff}); got != "abc" {
		t.Fatalf("valid TLV lost: %q", got)
	}
	p := Profile{IMSI: "310280000000001", MCC: "310", MNC: "280"}
	for _, id := range []Identity{{IMPI: "user@example.org\r\nInjected: value", IMPU: []string{"sip:user@example.org"}, Domain: "example.org"}, {IMPI: "user@example.org", IMPU: []string{"sip:user@example.org\x00"}, Domain: "example.org"}} {
		if _, err := PrepareStart(PrepareStartInput{Profile: p, Access: identityReader{identity: id}}); err == nil {
			t.Fatal("malformed ISIM identity accepted")
		}
	}
}
