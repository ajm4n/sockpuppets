"""Comprehensive tests for evasion.bof_packer module."""

from __future__ import annotations

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from evasion.bof_packer import BOFPacker, parse_bof_args


class TestBOFPackerAddInt:
    """add_int packs a 4-byte big-endian unsigned integer."""

    def test_zero(self):
        p = BOFPacker()
        p.add_int(0)
        assert p.pack() == b'\x00\x00\x00\x00'

    def test_small_value(self):
        p = BOFPacker()
        p.add_int(1)
        assert p.pack() == struct.pack('>I', 1)

    def test_large_value(self):
        p = BOFPacker()
        p.add_int(0xDEADBEEF)
        assert p.pack() == b'\xDE\xAD\xBE\xEF'

    def test_max_uint32(self):
        p = BOFPacker()
        p.add_int(0xFFFFFFFF)
        assert p.pack() == b'\xFF\xFF\xFF\xFF'

    def test_length_is_four_bytes(self):
        p = BOFPacker()
        p.add_int(42)
        assert len(p.pack()) == 4


class TestBOFPackerAddShort:
    """add_short packs a 2-byte big-endian unsigned short."""

    def test_zero(self):
        p = BOFPacker()
        p.add_short(0)
        assert p.pack() == b'\x00\x00'

    def test_small_value(self):
        p = BOFPacker()
        p.add_short(256)
        assert p.pack() == struct.pack('>H', 256)

    def test_max_uint16(self):
        p = BOFPacker()
        p.add_short(0xFFFF)
        assert p.pack() == b'\xFF\xFF'

    def test_length_is_two_bytes(self):
        p = BOFPacker()
        p.add_short(1)
        assert len(p.pack()) == 2


class TestBOFPackerAddStr:
    """add_str: 4-byte big-endian length prefix + UTF-8 encoded string + null terminator."""

    def test_simple_ascii(self):
        p = BOFPacker()
        p.add_str('hello')
        data = p.pack()
        # length prefix: len('hello') + 1 null = 6
        assert data[:4] == struct.pack('>I', 6)
        assert data[4:9] == b'hello'
        assert data[9:10] == b'\x00'

    def test_empty_string(self):
        p = BOFPacker()
        p.add_str('')
        data = p.pack()
        # length prefix: just the null terminator = 1
        assert data[:4] == struct.pack('>I', 1)
        assert data[4:5] == b'\x00'
        assert len(data) == 5

    def test_utf8_multibyte(self):
        p = BOFPacker()
        p.add_str('é')  # e-acute, 2 bytes in UTF-8
        data = p.pack()
        encoded = 'é'.encode('utf-8') + b'\x00'
        assert data[:4] == struct.pack('>I', len(encoded))
        assert data[4:] == encoded

    def test_null_terminator_present(self):
        p = BOFPacker()
        p.add_str('test')
        data = p.pack()
        # Last byte of the payload should be null
        length = struct.unpack('>I', data[:4])[0]
        assert data[4 + length - 1:4 + length] == b'\x00'


class TestBOFPackerAddWstr:
    """add_wstr: 4-byte big-endian length prefix + UTF-16LE encoded string + null terminator."""

    def test_simple_ascii(self):
        p = BOFPacker()
        p.add_wstr('AB')
        data = p.pack()
        encoded = 'AB'.encode('utf-16-le') + b'\x00\x00'
        assert data[:4] == struct.pack('>I', len(encoded))
        assert data[4:] == encoded

    def test_empty_string(self):
        p = BOFPacker()
        p.add_wstr('')
        data = p.pack()
        # Just the two-byte null terminator
        assert data[:4] == struct.pack('>I', 2)
        assert data[4:6] == b'\x00\x00'
        assert len(data) == 6

    def test_utf16le_encoding(self):
        p = BOFPacker()
        p.add_wstr('A')
        data = p.pack()
        # 'A' in UTF-16LE is 0x41 0x00, plus null term 0x00 0x00
        assert data[4:6] == b'\x41\x00'
        assert data[6:8] == b'\x00\x00'

    def test_double_null_terminator(self):
        p = BOFPacker()
        p.add_wstr('X')
        data = p.pack()
        length = struct.unpack('>I', data[:4])[0]
        # Last two bytes should be the null terminator
        assert data[4 + length - 2:4 + length] == b'\x00\x00'


class TestBOFPackerAddBinary:
    """add_binary: 4-byte big-endian length prefix + raw bytes."""

    def test_simple_bytes(self):
        p = BOFPacker()
        p.add_binary(b'\xDE\xAD')
        data = p.pack()
        assert data[:4] == struct.pack('>I', 2)
        assert data[4:] == b'\xDE\xAD'

    def test_empty_bytes(self):
        p = BOFPacker()
        p.add_binary(b'')
        data = p.pack()
        assert data[:4] == struct.pack('>I', 0)
        assert len(data) == 4

    def test_large_binary(self):
        blob = bytes(range(256)) * 4  # 1024 bytes
        p = BOFPacker()
        p.add_binary(blob)
        data = p.pack()
        assert data[:4] == struct.pack('>I', 1024)
        assert data[4:] == blob


class TestBOFPackerEmpty:
    """An unused packer returns empty bytes."""

    def test_empty_pack(self):
        p = BOFPacker()
        assert p.pack() == b''

    def test_empty_pack_length(self):
        p = BOFPacker()
        assert len(p.pack()) == 0


class TestBOFPackerMixed:
    """Multiple types packed in sequence are concatenated correctly."""

    def test_int_then_str(self):
        p = BOFPacker()
        p.add_int(7)
        p.add_str('hi')
        data = p.pack()

        # First 4 bytes: int 7
        assert data[:4] == struct.pack('>I', 7)
        # Next 4 bytes: string length (3: 'h','i','\0')
        assert data[4:8] == struct.pack('>I', 3)
        # Then the string payload
        assert data[8:11] == b'hi\x00'

    def test_short_int_wstr_binary(self):
        p = BOFPacker()
        p.add_short(10)
        p.add_int(20)
        p.add_wstr('Z')
        p.add_binary(b'\xFF')

        data = p.pack()
        offset = 0

        # short: 2 bytes
        assert struct.unpack('>H', data[offset:offset + 2])[0] == 10
        offset += 2

        # int: 4 bytes
        assert struct.unpack('>I', data[offset:offset + 4])[0] == 20
        offset += 4

        # wstr: 4-byte length + payload
        wstr_encoded = 'Z'.encode('utf-16-le') + b'\x00\x00'
        wstr_len = struct.unpack('>I', data[offset:offset + 4])[0]
        assert wstr_len == len(wstr_encoded)
        offset += 4
        assert data[offset:offset + wstr_len] == wstr_encoded
        offset += wstr_len

        # binary: 4-byte length + payload
        bin_len = struct.unpack('>I', data[offset:offset + 4])[0]
        assert bin_len == 1
        offset += 4
        assert data[offset:offset + 1] == b'\xFF'
        offset += 1

        assert offset == len(data)


class TestParseBofArgs:
    """parse_bof_args converts CLI-style type:value strings to packed binary."""

    def test_no_prefix_defaults_to_str(self):
        result = parse_bof_args(['hello'])
        p = BOFPacker()
        p.add_str('hello')
        assert result == p.pack()

    def test_str_prefix(self):
        result = parse_bof_args(['str:world'])
        p = BOFPacker()
        p.add_str('world')
        assert result == p.pack()

    def test_int_prefix(self):
        result = parse_bof_args(['int:42'])
        p = BOFPacker()
        p.add_int(42)
        assert result == p.pack()

    def test_short_prefix(self):
        result = parse_bof_args(['short:1024'])
        p = BOFPacker()
        p.add_short(1024)
        assert result == p.pack()

    def test_wstr_prefix(self):
        result = parse_bof_args(['wstr:test'])
        p = BOFPacker()
        p.add_wstr('test')
        assert result == p.pack()

    def test_bin_prefix_reads_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'\xCA\xFE\xBA\xBE')
            tmp_path = tmp.name
        try:
            result = parse_bof_args([f'bin:{tmp_path}'])
            p = BOFPacker()
            p.add_binary(b'\xCA\xFE\xBA\xBE')
            assert result == p.pack()
        finally:
            os.unlink(tmp_path)

    def test_empty_args(self):
        result = parse_bof_args([])
        assert result == b''

    def test_mixed_typed_args(self):
        result = parse_bof_args(['int:100', 'str:foo', 'short:5', 'wstr:bar'])
        p = BOFPacker()
        p.add_int(100)
        p.add_str('foo')
        p.add_short(5)
        p.add_wstr('bar')
        assert result == p.pack()

    def test_str_with_colon_in_value(self):
        # "str:key:value" should treat everything after "str:" as the value
        result = parse_bof_args(['str:key:value'])
        p = BOFPacker()
        p.add_str('key:value')
        assert result == p.pack()

    def test_no_prefix_with_colon_not_matching_type(self):
        # "unknown:stuff" doesn't match any known prefix, defaults to str
        result = parse_bof_args(['unknown:stuff'])
        p = BOFPacker()
        p.add_str('unknown:stuff')
        assert result == p.pack()
