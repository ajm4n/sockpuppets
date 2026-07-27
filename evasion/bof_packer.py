from __future__ import annotations

import struct


class BOFPacker:
    """Pack arguments for BOF execution using Cobalt Strike's wire format."""

    def __init__(self):
        self._buf = bytearray()

    def add_int(self, val: int):
        self._buf += struct.pack('>I', val)

    def add_short(self, val: int):
        self._buf += struct.pack('>H', val)

    def add_str(self, val: str):
        encoded = val.encode('utf-8') + b'\x00'
        self._buf += struct.pack('>I', len(encoded))
        self._buf += encoded

    def add_wstr(self, val: str):
        encoded = val.encode('utf-16-le') + b'\x00\x00'
        self._buf += struct.pack('>I', len(encoded))
        self._buf += encoded

    def add_binary(self, val: bytes):
        self._buf += struct.pack('>I', len(val))
        self._buf += val

    def pack(self) -> bytes:
        return bytes(self._buf)


def parse_bof_args(args: list[str]) -> bytes:
    """Parse CLI-style type:value args into packed binary.

    Supported prefixes: int:, short:, str:, wstr:, bin: (file path).
    No prefix defaults to str:.
    """
    packer = BOFPacker()
    for arg in args:
        if arg.startswith('int:'):
            packer.add_int(int(arg[4:]))
        elif arg.startswith('short:'):
            packer.add_short(int(arg[6:]))
        elif arg.startswith('wstr:'):
            packer.add_wstr(arg[5:])
        elif arg.startswith('bin:'):
            with open(arg[4:], 'rb') as f:
                packer.add_binary(f.read())
        elif arg.startswith('str:'):
            packer.add_str(arg[4:])
        else:
            packer.add_str(arg)
    return packer.pack()
