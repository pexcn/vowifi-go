"""Generate synthetic RFC 5282 SKF bytes independently of the Go codecs."""
import json
import pathlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

path = pathlib.Path(__file__).parent
fixture = json.loads((path / "ike_fragment_replay.json").read_text())
key, salt = bytes(range(16)), bytes([0x41, 0x42, 0x43, 0x44])
plain = bytes.fromhex(fixture["plaintext"])
chunks = [plain[i:i + 280] for i in range(0, len(plain), 280)]
packets = []
for number, chunk in enumerate(chunks, 1):
    pad = 3 - len(chunk) % 4
    padded = chunk + bytes(pad) + bytes([pad])
    iv = number.to_bytes(8, "big")
    skf = bytes([36 if number == 1 else 0, 0]) + struct.pack(
        "!HHH", 8 + 8 + len(padded) + 16, number, len(chunks)
    )
    prefix = struct.pack(
        "!QQBBBBII", 0x0102030405060708, 0x1112131415161718,
        53, 32, 35, 32, 1, 28 + 8 + 8 + len(padded) + 16,
    ) + skf
    wire = prefix + iv + AESGCM(key).encrypt(salt + iv, padded, prefix)
    packets.append(wire.hex())
fixture.update({
    "provenance": "Synthetic deidentified RFC 5282/7383 fixture; Python cryptography AESGCM; not a carrier capture. Opaque certificate test data is not authentication evidence.",
    "encryption_key": (key + salt).hex(), "integrity_key": "", "packets": packets,
})
(path / "ike_gcm_fragment_replay.json").write_text(json.dumps(fixture, indent=2) + "\n")
