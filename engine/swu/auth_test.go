package swu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestIKECertificateEKUAndMethodBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("verified responder signed octets")
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	for _, purpose := range []string{"ike", "server", "any", "absent", "email"} {
		t.Run(purpose, func(t *testing.T) {
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"epdg.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
			switch purpose {
			case "ike":
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidIPSECIKE}
			case "server":
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "any":
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
			case "email":
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			input := ResponderAuthInput{Method: 9, Certificates: [][]byte{der}, SignedOctets: message, Authentication: sig}
			err = VerifyCertificateAuth(input, "epdg.test", roots)
			if purpose == "email" {
				if err == nil {
					t.Fatal("unrelated EKU accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyCertificateAuth(input, "wrong.test", roots); err == nil {
				t.Fatal("hostname not bound")
			}
			if err = VerifyCertificateAuth(input, "epdg.test", x509.NewCertPool()); err == nil {
				t.Fatal("untrusted chain accepted")
			}
			input.Method = 10
			if err = VerifyCertificateAuth(input, "epdg.test", roots); err == nil {
				t.Fatal("method10 with P256 accepted")
			}
		})
	}
}
func TestCertificatePurposeMustHoldAcrossEntireChain(t *testing.T) {
	server := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	ike := &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidIPSECIKE}}
	chain := []*x509.Certificate{ike, server}
	if chainPermitsIKEPurpose(chain, true) || chainPermitsIKEPurpose(chain, false) {
		t.Fatal("chain EKUs used as union rather than intersection")
	}
}
