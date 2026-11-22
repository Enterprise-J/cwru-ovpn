import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 2
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_RPATH = 0x8000001C


def commands(image):
    if len(image) < 32:
        raise ValueError("Missing Mach-O header")
    magic, cpu, _, kind, count, size = struct.unpack_from("<6I", image)
    if (magic, cpu, kind) != (MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE) or size > len(image) - 32:
        raise ValueError("Expected a thin arm64 executable")
    offset = 32
    for _ in range(count):
        if offset + 8 > 32 + size:
            raise ValueError("Missing Mach-O load command")
        command, length = struct.unpack_from("<II", image, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError("Invalid Mach-O load command")
        yield command, offset, length
        offset += length
    if offset != 32 + size:
        raise ValueError("Inconsistent Mach-O command size")


def finalize(path):
    image = path.read_bytes()
    remove = []
    for command, offset, length in commands(image):
        if command == LC_RPATH:
            string_offset, = struct.unpack_from("<I", image, offset + 8)
            if not 12 <= string_offset < length:
                raise ValueError("Invalid RPATH")
            name, terminator, _ = image[offset + string_offset:offset + length].partition(b"\0")
            if not name or not terminator:
                raise ValueError("Invalid RPATH string")
            remove.extend(["-delete_rpath", os.fsdecode(name)])
    if remove:
        subprocess.run(["/usr/bin/install_name_tool", *remove, path], check=True)
    if any(command == LC_CODE_SIGNATURE for command, _, _ in commands(path.read_bytes())):
        subprocess.run(["/usr/bin/codesign", "--remove-signature", path], check=True)

    image = bytearray(path.read_bytes())
    identifiers = []
    for command, offset, length in commands(image):
        if command in (LC_CODE_SIGNATURE, LC_RPATH):
            raise ValueError("Unfinalized Mach-O load command")
        if command == LC_UUID and length == 24:
            identifiers.append(offset + 8)
    if len(identifiers) != 1:
        raise ValueError("Expected one build UUID")
    offset = identifiers[0]
    image[offset:offset + 16] = bytes(16)
    identifier = bytearray(hashlib.sha256(image).digest()[:16])
    identifier[6] = (identifier[6] & 0x0F) | 0x80
    identifier[8] = (identifier[8] & 0x3F) | 0x80
    with path.open("r+b") as executable:
        executable.seek(offset)
        executable.write(identifier)


finalize(Path(sys.argv[1]))
