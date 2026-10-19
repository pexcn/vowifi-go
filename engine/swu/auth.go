package swu

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"math/big"
)

type ResponderAuthInput struct {
	Identity                     []byte
	Certificates                 [][]byte
	Method                       byte
	SignedOctets, Authentication []byte
}
type ResponderVerifier func(ResponderAuthInput) error

func signedOctets(p vc.PRF, init, nonce, skp, id []byte) ([]byte, error) {
	m, e := p.Sum(skp, id)
	if e != nil {
		return nil, e
	}
	out := append(append([]byte{}, init...), nonce...)
	return append(out, m...), nil
}
func sharedAuth(p vc.PRF, key, octets []byte) ([]byte, error) {
	k, e := p.Sum(key, []byte("Key Pad for IKEv2"))
	if e != nil {
		return nil, e
	}
	return p.Sum(k, octets)
}
func newBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
func (s *Session) verifyResponder(ps []ikev2.Payload, msk []byte) error {
	id, e := ikev2.One(ps, ikev2.IDr)
	if e != nil {
		if _, present := ikev2.Find(ps, ikev2.IDr); !present && len(msk) > 0 && len(s.responderID) > 0 {
			id = s.responderID
		} else {
			return e
		}
	} else {
		s.responderID = append([]byte{}, id...)
	}
	if len(id) < 5 || id[1] != 0 || id[2] != 0 || id[3] != 0 {
		return errors.New("invalid responder ID")
	}
	auth, e := ikev2.One(ps, ikev2.AUTH)
	if e != nil {
		return e
	}
	if len(auth) < 5 || auth[1] != 0 || auth[2] != 0 || auth[3] != 0 {
		return errors.New("invalid responder AUTH")
	}
	octets, e := signedOctets(s.prf, s.initResponse, s.ni, s.keys.SKpr, id)
	if e != nil {
		return e
	}
	if auth[0] == 2 {
		if len(msk) == 0 {
			return errors.New("responder shared-key AUTH before EAP success")
		}
		want, e := sharedAuth(s.prf, msk, octets)
		if e != nil {
			return e
		}
		if !hmac.Equal(want, auth[4:]) {
			return errors.New("responder MSK AUTH mismatch")
		}
		return nil
	}
	in := ResponderAuthInput{Identity: append([]byte{}, id...), Method: auth[0], SignedOctets: octets, Authentication: auth[4:]}
	for _, p := range ps {
		if p.Type == ikev2.CERT {
			if len(p.Data) < 2 || p.Data[0] != 4 {
				return errors.New("only X.509 signature certificates supported")
			}
			in.Certificates = append(in.Certificates, append([]byte{}, p.Data[1:]...))
		}
	}
	if s.cfg.ResponderVerifier != nil {
		return s.cfg.ResponderVerifier(in)
	}
	return VerifyCertificateAuth(in, s.cfg.ServerName, s.cfg.Roots)
}

// VerifyCertificateAuth binds the signing key to a validated X.509 server chain and
// configured ePDG hostname. No missing-AUTH or untrusted-certificate fallback exists.
func VerifyCertificateAuth(in ResponderAuthInput, serverName string, roots *x509.CertPool) error {
	if serverName == "" || len(in.Certificates) == 0 {
		return errors.New("responder hostname and certificate required")
	}
	leaf, e := x509.ParseCertificate(in.Certificates[0])
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	for _, der := range in.Certificates[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return e
		}
		pool.AddCert(c)
	}
	chains, e := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if e != nil {
		return fmt.Errorf("responder certificate: %w", e)
	}
	// Go has no ExtKeyUsage constant for RFC4945 id-kp-ipsecIKE. Validate
	// purposes over the entire verified chain ourselves; serverAuth remains a
	// supported ePDG certificate profile. Unrelated EKUs never grant IKE use.
	permitted := false
	for _, chain := range chains {
		if chainPermitsIKEPurpose(chain, false) || chainPermitsIKEPurpose(chain, true) {
			permitted = true
			break
		}
	}
	if !permitted {
		return errors.New("responder certificate EKU does not permit IKE or server authentication")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate disallows signatures")
	}
	var hash crypto.Hash
	sig := in.Authentication
	kind := ""
	switch in.Method {
	case 1:
		hash = crypto.SHA1
		kind = "rsa"
	case 9:
		hash = crypto.SHA256
		kind = "ecdsa-raw"
	case 10:
		hash = crypto.SHA384
		kind = "ecdsa-raw"
	case 11:
		hash = crypto.SHA512
		kind = "ecdsa-raw"
	case 14:
		if len(sig) < 2 || int(sig[0])+1 >= len(sig) {
			return errors.New("invalid RFC7427 AUTH")
		}
		n := int(sig[0])
		var alg struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		rest, e := asn1.Unmarshal(sig[1:1+n], &alg)
		if e != nil || len(rest) != 0 {
			return errors.New("invalid signature AlgorithmIdentifier")
		}
		switch alg.OID.String() {
		case "1.2.840.113549.1.1.11":
			hash = crypto.SHA256
			kind = "rsa"
		case "1.2.840.113549.1.1.12":
			hash = crypto.SHA384
			kind = "rsa"
		case "1.2.840.113549.1.1.13":
			hash = crypto.SHA512
			kind = "rsa"
		case "1.2.840.10045.4.3.2":
			hash = crypto.SHA256
			kind = "ecdsa"
		case "1.2.840.10045.4.3.3":
			hash = crypto.SHA384
			kind = "ecdsa"
		case "1.2.840.10045.4.3.4":
			hash = crypto.SHA512
			kind = "ecdsa"
		default:
			return errors.New("unsupported RFC7427 signature algorithm")
		}
		sig = sig[1+n:]
	default:
		return fmt.Errorf("unsupported responder AUTH method %d", in.Method)
	}
	var digest []byte
	switch hash {
	case crypto.SHA1:
		h := sha1.Sum(in.SignedOctets)
		digest = h[:]
	case crypto.SHA256:
		h := sha256.Sum256(in.SignedOctets)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(in.SignedOctets)
		digest = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(in.SignedOctets)
		digest = h[:]
	}
	switch kind {
	case "rsa":
		key, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("AUTH key type mismatch")
		}
		return rsa.VerifyPKCS1v15(key, hash, digest, sig)
	case "ecdsa", "ecdsa-raw":
		key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("AUTH key type mismatch")
		}
		if kind == "ecdsa-raw" {
			wantBits := map[byte]int{9: 256, 10: 384, 11: 521}[in.Method]
			if key.Curve.Params().BitSize != wantBits {
				return errors.New("ECDSA AUTH curve does not match method")
			}
			n := (key.Curve.Params().BitSize + 7) / 8
			if len(sig) != 2*n {
				return errors.New("wrong ECDSA signature length")
			}
			r := newBig(sig[:n])
			ss := newBig(sig[n:])
			if !ecdsa.Verify(key, digest, r, ss) {
				return errors.New("ECDSA AUTH verification failed")
			}
			return nil
		}
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return errors.New("ECDSA AUTH verification failed")
		}
		return nil
	}
	return errors.New("unsupported AUTH")
}

var oidIPSECIKE = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 2, 2}

func chainPermitsIKEPurpose(chain []*x509.Certificate, ike bool) bool {
	for _, cert := range chain {
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}
		allowed := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny || !ike && usage == x509.ExtKeyUsageServerAuth {
				allowed = true
			}
		}
		if ike {
			for _, usage := range cert.UnknownExtKeyUsage {
				if usage.Equal(oidIPSECIKE) {
					allowed = true
				}
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}
