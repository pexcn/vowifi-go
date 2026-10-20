package ims

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"unicode/utf8"

	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

// Decode one unambiguous RPDU. Nested multipart, conflicting SMS parts and
// unsupported transfer encodings fail closed instead of guessing a payload.
func smsBody(m *message) ([]byte, error) {
	if len(m.Body) > 65536 {
		return nil, errors.New("SMS body too large")
	}
	kind, params, err := mime.ParseMediaType(m.get("content-type"))
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(kind, "application/vnd.3gpp.sms") {
		return smsTransfer(m.Body, m.get("content-transfer-encoding"))
	}
	if !strings.EqualFold(kind, "multipart/mixed") || params["boundary"] == "" {
		return nil, errors.New("unsupported SMS content type")
	}
	reader := multipart.NewReader(bytes.NewReader(m.Body), params["boundary"])
	var result []byte
	for n := 0; n < 8; n++ {
		part, e := reader.NextRawPart()
		if e == io.EOF {
			if result == nil {
				return nil, errors.New("multipart has no SMS")
			}
			return result, nil
		}
		if e != nil {
			return nil, e
		}
		media, _, e := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if e != nil {
			return nil, e
		}
		body, e := io.ReadAll(io.LimitReader(part, 65537))
		part.Close()
		if e != nil || len(body) > 65536 {
			return nil, errors.New("invalid SMS MIME part")
		}
		if strings.EqualFold(media, "application/vnd.3gpp.sms") {
			if result != nil {
				return nil, errors.New("multiple SMS MIME parts")
			}
			result, e = smsTransfer(body, part.Header.Get("Content-Transfer-Encoding"))
			if e != nil {
				return nil, e
			}
		} else if strings.HasPrefix(strings.ToLower(media), "multipart/") {
			return nil, errors.New("nested SMS multipart unsupported")
		}
	}
	return nil, errors.New("too many SMS MIME parts")
}
func smsTransfer(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "binary", "8bit":
		return body, nil
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, body)
		return base64.StdEncoding.Strict().DecodeString(string(clean))
	default:
		return nil, errors.New("unsupported SMS transfer encoding")
	}
}
func decodeInboundParts(parts []*tpdu.TPDU) ([]byte, error) {
	if len(parts) == 0 {
		return nil, errors.New("empty SMS")
	}
	data, err := smscodec.Decode(parts)
	if err != nil {
		return nil, err
	}
	alpha, err := parts[0].DCS.Alphabet()
	if err != nil {
		return nil, err
	}
	if alpha == tpdu.Alpha8Bit {
		header := "[Binary SMS]"
		if parts[0].PID == 0x7f {
			header = "[SIM OTA 23.048]\ndecrypt=not_attempted"
		}
		return []byte(fmt.Sprintf("%s\nPID=%02x DCS=%02x\nUDH=%v\nraw=%s", header, byte(parts[0].PID), byte(parts[0].DCS), parts[0].UDH, hex.EncodeToString(data))), nil
	}
	if !utf8.Valid(data) {
		return nil, errors.New("invalid SMS text")
	}
	return data, nil
}
