package media

import (
	"encoding/binary"
	"errors"
	"strings"
)

func validateEncodedMedia(packet []byte, codec Codec) error {
	name := strings.ToUpper(codec.Name)
	if name != "AMR" && name != "AMR-WB" {
		return nil
	}
	if !validRTP(packet) {
		return errors.New("invalid AMR RTP")
	}
	offset := 12 + 4*int(packet[0]&15)
	if packet[0]&16 != 0 {
		offset += 4 + 4*int(binary.BigEndian.Uint16(packet[offset+2:]))
	}
	end := len(packet)
	if packet[0]&32 != 0 {
		end -= int(packet[end-1])
	}
	payload := packet[offset:end]
	if len(payload) < 2 || payload[0]&15 != 0 {
		return errors.New("invalid AMR CMR")
	}
	maximum := byte(7)
	bits := []int{95, 103, 118, 134, 148, 159, 204, 244, 39, -1, -1, -1, -1, -1, -1, 0}
	if name == "AMR-WB" {
		maximum = 8
		bits = []int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40, -1, -1, -1, -1, 0, 0}
	}
	if cmr := payload[0] >> 4; cmr > maximum && cmr != 15 {
		return errors.New("unsupported AMR codec mode")
	}
	expected := 0
	position := 1
	for {
		if position >= len(payload) || position > 32 {
			return errors.New("invalid AMR TOC")
		}
		toc := payload[position]
		position++
		ft := int(toc >> 3 & 15)
		if toc&3 != 0 || bits[ft] < 0 {
			return errors.New("unsupported AMR frame type")
		}
		expected += (bits[ft] + 7) / 8
		if toc&128 == 0 {
			break
		}
	}
	if len(payload)-position != expected {
		return errors.New("AMR payload frame length mismatch")
	}
	return nil
}
