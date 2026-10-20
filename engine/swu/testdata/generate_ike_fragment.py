"""Regenerate the synthetic fixture using Python framing/HMAC and OpenSSL CBC.

All identities, SPIs, keys and IVs are test data. No live capture is read.
Go replay tests use the saved JSON and do not require Python or OpenSSL.
"""
import hashlib
import hmac
import json
import pathlib
import struct
import subprocess

enc = bytes(range(16))
auth = bytes(range(32, 64))


def payload(next_type, data):
    return bytes([next_type, 0]) + struct.pack("!H", 4 + len(data)) + data


plain = (
    payload(37, b"\x02\0\0\0epdg.invalid")
    + payload(41, b"\x04" + bytes(range(240)) * 3)
    + payload(0, b"\0\0\x40\x1e")
)
chunks = [plain[i:i + 280] for i in range(0, len(plain), 280)]
packets = []
for number, chunk in enumerate(chunks, 1):
    pad = 15 - len(chunk) % 16
    padded = chunk + bytes(pad) + bytes([pad])
    iv = bytes([0x90 + number]) * 16
    ciphertext = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-K", enc.hex(), "-iv", iv.hex(), "-nopad"],
        input=padded, stdout=subprocess.PIPE, check=True,
    ).stdout
    body = (
        bytes([36 if number == 1 else 0, 0])
        + struct.pack("!HHH", 8 + 16 + len(ciphertext) + 16, number, len(chunks))
        + iv + ciphertext
    )
    header = struct.pack(
        "!QQBBBBII", 0x0102030405060708, 0x1112131415161718,
        53, 32, 35, 32, 1, 28 + len(body) + 16,
    )
    wire = header + body
    wire += hmac.new(auth, wire, hashlib.sha256).digest()[:16]
    packets.append(wire.hex())

fixture = {
    "provenance": (
        "Synthetic deidentified RFC 7383 IKE_AUTH fixture; Python framing/HMAC "
        "and OpenSSL AES-128-CBC; not a carrier capture. Certificate bytes are "
        "opaque codec test data, not authentication evidence."
    ),
    "encryption_key": enc.hex(),
    "integrity_key": auth.hex(),
    "first_payload": 36,
    "plaintext": plain.hex(),
    "packets": packets,
    "events": [
        {"packet": 2, "result": "pending"},
        {"packet": 2, "result": "pending"},
        {"packet": 0, "result": "pending"},
        {"packet": 1, "tamper": True, "result": "reject"},
        {"packet": 1, "result": "complete"},
    ],
}
path = pathlib.Path(__file__).with_name("ike_fragment_replay.json")
path.write_text(json.dumps(fixture, indent=2) + "\n")
