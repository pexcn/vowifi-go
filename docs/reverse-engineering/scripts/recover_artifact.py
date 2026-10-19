#!/usr/bin/env python3
"""Read one pinned ELF's carrier assets/type descriptors/default data, never execute it.

No third-party Python packages. Addresses are specific to the SHA-256 below.
This is local static evidence, not REA provider output or recovered source code.
"""
import argparse
import hashlib
import json
import pathlib
import struct

EXPECTED = "2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f"


class Artifact:
    def __init__(self, path):
        self.data = path.read_bytes()
        if hashlib.sha256(self.data).hexdigest() != EXPECTED:
            raise ValueError("SHA-256 differs; this extractor's addresses are not applicable")
        if self.data[:6] != b"\x7fELF\x02\x01":
            raise ValueError("expected ELF64 little-endian")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data)
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", self.data, header[6] + i * header[11])
                         for i in range(header[12])]
        names = self.sections[header[13]]
        self.names = self.data[names[4]:names[4] + names[5]]
        self.rodata = self.section(".rodata")[3]

    def section(self, name):
        for sec in self.sections:
            if self.names[sec[0]:].split(b"\0", 1)[0].decode() == name:
                return sec
        raise ValueError("missing ELF section " + name)

    def read(self, address, length):
        if length < 0 or length > len(self.data):
            raise ValueError("invalid read length")
        for sec in self.sections:
            if sec[2] & 2 and sec[3] <= address and address + length <= sec[3] + sec[5]:
                if sec[1] == 8:
                    return bytes(length)
                off = sec[4] + address - sec[3]
                if off + length > len(self.data):
                    raise ValueError("read exceeds file")
                return self.data[off:off + length]
        raise ValueError("unmapped VA: " + hex(address))

    def q(self, address, count=1):
        return struct.unpack("<" + "Q" * count, self.read(address, 8 * count))

    def name(self, address):
        size, shift = 0, 0
        for i in range(10):
            byte = self.read(address + 1 + i, 1)[0]
            size |= (byte & 127) << shift
            if byte < 128:
                return self.read(address + 2 + i, size).decode()
            shift += 7
        raise ValueError("unbounded name varint")

    def typename(self, address):
        off = struct.unpack("<i", self.read(address + 40, 4))[0]
        value = self.name(self.rodata + off)
        return value[1:] if self.read(address + 20, 1)[0] & 2 else value

    def fields(self, address):
        base, count, capacity = self.q(address + 56, 3)
        if count > capacity or count > 4096:
            raise ValueError("invalid struct field count")
        result = []
        for i in range(count):
            name, typ, offset = self.q(base + i * 24, 3)
            result.append({"name": self.name(name), "type": self.typename(typ),
                           "type_va": hex(typ), "offset": offset, "size": self.q(typ)[0]})
        return result

    def decode(self, address, typ, depth=0):
        if depth > 20:
            raise ValueError("recursive descriptor")
        kind, size = self.read(typ + 23, 1)[0] & 31, self.q(typ)[0]
        if kind == 24:
            data, length = self.q(address, 2)
            return self.read(data, length).decode() if length else ""
        if kind == 1:
            return bool(self.read(address, 1)[0])
        if 2 <= kind <= 12:
            return int.from_bytes(self.read(address, size), "little", signed=kind <= 6)
        if kind == 25:
            return {f["name"]: self.decode(address + f["offset"], int(f["type_va"], 16), depth + 1)
                    for f in self.fields(typ)}
        if kind == 23:
            base, count, capacity = self.q(address, 3)
            if count > capacity or count > 100000:
                raise ValueError("invalid slice")
            element = self.q(typ + 48)[0]
            step = self.q(element)[0]
            return [self.decode(base + i * step, element, depth + 1) for i in range(count)]
        return {"kind": kind, "raw": self.read(address, size).hex()}

    def string(self, address):
        data, size = self.q(address, 2)
        return self.read(data, size).decode() if size else ""


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def recover(artifact, output):
    output.mkdir(parents=True, exist_ok=True)
    assets = output / "presets"
    assets.mkdir(exist_ok=True)
    base, count, capacity = artifact.q(artifact.q(0x3B16170)[0], 3)
    if (count, capacity) != (17, 17):
        raise ValueError("unexpected embedded-FS records")
    manifest = []
    for i in range(count):
        record = base + i * 48
        name, name_size, data, size = artifact.q(record, 4)
        filename = artifact.read(name, name_size).decode()
        if filename == "presets/" and size == 0:
            continue
        if not filename.startswith("presets/") or pathlib.PurePosixPath(filename).name != filename[8:]:
            raise ValueError("unexpected embedded filename")
        value = artifact.read(data, size)
        (assets / pathlib.PurePosixPath(filename).name).write_bytes(value)
        manifest.append({"name": filename, "record_va": hex(record), "data_va": hex(data),
                         "length": size, "sha256": hashlib.sha256(value).hexdigest()})
    save(output / "presets-manifest.json", manifest)
    eff = artifact.decode(0x27D4DD8, 0x2178D60)
    for field, address in {"EPDGPort":0x3A4D610,"NATKeepaliveSeconds":0x3A4D618,
                           "DPDIntervalSeconds":0x3A4D620,"IMSLocalPort":0x3A4D628,
                           "IMSTCPKeepaliveSeconds":0x3A4D630,"IMSOptionsPingIntervalSeconds":0x3A4D638}.items():
        eff[field] = artifact.q(address)[0]
    for field, address in {"APN":0x3B188E0,"DNSServer":0x3B47970,"AKAChallengeMode":0x3B188F0,
                           "IKEIdentityMode":0x3B18900,"AKAIdentityMode":0x3B18910,
                           "DeviceModel":0x3B18940,"IMSTransport":0x3B18920}.items():
        eff[field] = artifact.string(address)
    for field, address in {"IKEProposals":0x3B213D0,"ESPProposals":0x3B213F0}.items():
        eff[field] = artifact.decode(address, 0x1C208C0)
    eff["EPDGAddr"] = "<DefaultCarrierStandardEPDGAddr(MCC,MNC)>"
    eff["IMSDomain"] = eff["IMSRealm"] = "<DefaultCarrierIMSDomain(MCC,MNC)>"
    template = artifact.decode(0x27C6238, 0x2155DA0)
    template["SMSReceiverTransport"] = artifact.string(0x3B18930)
    template["ContactParamOrder"] = [artifact.read(addr, size).decode() for addr, size in
                                     [(0x21B3424,11),(0x21B53F9,12),(0x21A2AC6,5),(0x21A1CE8,5),(0x21ADDAC,8)]]
    fields = {f["name"]:int(f["type_va"],16) for f in artifact.fields(0x2155DA0)}
    template["SecurityClientMechanisms"] = artifact.decode(0x3B21350, fields["SecurityClientMechanisms"])
    retry = {f["name"]:int(f["type_va"],16) for f in artifact.fields(fields["RegisterPolicy"])}
    for field, address in {"TemporaryStatusCodes":0x3B21370,"ForbiddenStatusCodes":0x3B21390,
                           "InitialRejectFallbackStatusCodes":0x3B213B0}.items():
        template["RegisterPolicy"][field] = artifact.decode(address, retry[field])
    template["RegisterPolicy"]["TemporaryRetrySeconds"] = artifact.q(0x3A4D640)[0]
    eff["IMSRegisterTemplate"] = template
    save(output / "defaults.json", eff)
    types = []
    links = artifact.section(".typelink")
    for i in range(links[5] // 4):
        offset = struct.unpack("<i", artifact.read(links[3] + i * 4, 4))[0]
        address = artifact.rodata + offset
        name = artifact.typename(address)
        if not any(key in name for key in ("Carrier", "IMSRegister", "swu.Config", "IPSec3GPPSecurity", "policy.E911", "swu.Session")):
            continue
        kind = artifact.read(address + 23, 1)[0] & 31
        value = {"name":name,"va":hex(address),"kind":kind,"size":artifact.q(address)[0]}
        struct_address = artifact.q(address + 48)[0] if kind == 22 else address
        if artifact.read(struct_address + 23,1)[0] & 31 == 25:
            value["fields"] = artifact.fields(struct_address)
            value["struct_va"] = hex(struct_address)
        types.append(value)
    save(output / "types.json", types)
    save(output / "provenance.json", {"target_sha256": EXPECTED,"bytes":len(artifact.data),
         "method":"local-static-elf-and-go-runtime-descriptors", "target_executed":False,
         "limitations":["Specific target addresses only","Initialized global values plus observed assignment sites; not runtime coverage","Not REA evidence or original source"]})
    print(f"Extracted {len(manifest)} carrier YAML assets, defaults and {len(types)} type records into {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    recover(Artifact(args.binary), args.output)
