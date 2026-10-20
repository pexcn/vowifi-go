package ikev2

import (
	"encoding/binary"
	"errors"
	"io"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
)

const (
	SKF                    byte   = 53
	FragmentationSupported uint16 = 16430
	MaxFragments                  = 255
	MaxFragmentedSize             = 64 * 1024
)

// Fragment contains only authenticated, decrypted RFC 7383 fragment data.
// Payloads cannot be parsed until the entire plaintext chain is reassembled.
type Fragment struct {
	Header        Header
	Number, Total uint16
	FirstPayload  byte
	Plaintext     []byte
}

// SealFragments uses SK for small messages and SKF for larger ones. maxPacket
// bounds IKE bytes only; the caller reserves outer IP/UDP/Non-ESP headers.
// Call this only after both peers have advertised fragmentation support.
func SealFragments(h Header, ps []Payload, enc, integ []byte, alg vc.Integrity, rng io.Reader, maxPacket int) ([][]byte, error) {
	return SealFragmentsProtected(h, ps, enc, integ, vc.Protection{Encryption: vc.AESCBC, Integrity: alg}, rng, maxPacket)
}
func SealFragmentsProtected(h Header, ps []Payload, enc, integ []byte, suite vc.Protection, rng io.Reader, maxPacket int) ([][]byte, error) {
	if maxPacket < 84 || !suite.Valid() || maxPacket < 36+suite.IVSize()+suite.Alignment()+suite.TagSize() || maxPacket > 65535 {
		return nil, errors.New("invalid IKE fragment packet limit")
	}
	if h.Exchange == SAInit {
		return nil, errors.New("IKE_SA_INIT cannot be fragmented")
	}
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		return nil, err
	}
	if len(plain) > MaxFragmentedSize {
		return nil, errors.New("fragmented IKE message too large")
	}
	if !suite.Valid() {
		return nil, errors.New("unsupported IKE integrity")
	}
	block := suite.Alignment()
	padded := (len(plain)/block + 1) * block
	if 32+suite.IVSize()+padded+suite.TagSize() <= maxPacket {
		b, err := sealProtected(h, first, plain, nil, enc, integ, suite, rng)
		if err != nil {
			return nil, err
		}
		return [][]byte{b}, nil
	}
	// Each fragment has 28 IKE + 8 SKF headers, 16 IV, an integral number
	// of CBC blocks (including at least one padding byte), and the ICV.
	capacity := ((maxPacket-36-suite.IVSize()-suite.TagSize())/block)*block - 1
	if capacity <= 0 {
		return nil, errors.New("invalid IKE fragment packet limit")
	}
	total := (len(plain) + capacity - 1) / capacity
	if total == 0 || total > MaxFragments {
		return nil, errors.New("too many IKE fragments")
	}
	packets := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		next := byte(0)
		if i == 0 {
			next = first
		}
		fh := binary.BigEndian.AppendUint16(nil, uint16(i+1))
		fh = binary.BigEndian.AppendUint16(fh, uint16(total))
		end := min((i+1)*capacity, len(plain))
		wire, err := sealProtected(h, next, plain[i*capacity:end], fh, enc, integ, suite, rng)
		if err != nil {
			return nil, err
		}
		packets = append(packets, wire)
	}
	return packets, nil
}

func OpenFragment(b, enc, integ []byte, alg vc.Integrity) (Fragment, error) {
	return OpenFragmentProtected(b, enc, integ, vc.Protection{Encryption: vc.AESCBC, Integrity: alg})
}
func OpenFragmentProtected(b, enc, integ []byte, suite vc.Protection) (Fragment, error) {
	h, plain, err := openProtected(b, enc, integ, suite, SKF, 36)
	if err != nil {
		return Fragment{}, err
	}
	number, total := binary.BigEndian.Uint16(b[32:]), binary.BigEndian.Uint16(b[34:])
	if h.Exchange == SAInit || number == 0 || total == 0 || number > total || total > MaxFragments || number > 1 && b[28] != 0 {
		return Fragment{}, errors.New("invalid IKE fragment metadata")
	}
	return Fragment{h, number, total, b[28], plain}, nil
}
