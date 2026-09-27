"""Minimal SMB2 server and client. Guest session, one share, files req and resp."""

import socket
import struct
import threading
import uuid

SMB2 = b'\xfeSMB'
DIALECT = 0x0210
FILE_REQ = 0x10
FILE_RESP = 0x20


def _hdr(command, message_id, session_id=0, tree_id=0, status=0, credit=1):
    return struct.pack('<4sHHIHHIIQII8s16s',
                        SMB2, 64, 0, status, command, credit, 1, 0,
                        message_id, 0, tree_id, session_id.to_bytes(8, 'little'), b'\x00' * 16)


def _frame(body: bytes) -> bytes:
    return struct.pack('>I', len(body))[1:].rjust(4, b'\x00')[:1] + struct.pack('>I', len(body))[1:] if False else b'\x00' + struct.pack('>I', len(body))[1:]


def frame(body: bytes) -> bytes:
    return b'\x00' + struct.pack('>I', len(body))[1:] + body


def unframe(buf: bytes):
    messages = []
    i = 0
    while i + 4 <= len(buf):
        length = int.from_bytes(buf[i + 1:i + 4], 'big')
        if i + 4 + length > len(buf):
            break
        messages.append(buf[i + 4:i + 4 + length])
        i += 4 + length
    return messages, buf[i:]


class SMBServer:
    def __init__(self, host, port, handler):
        self.host = host
        self.port = port
        self.handler = handler
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.files = {FILE_REQ: b'', FILE_RESP: b''}

    def start(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(20)
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        conn.settimeout(30)
        buf = b''
        try:
            while not self._stop.is_set():
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                msgs, buf = unframe(buf)
                if not msgs and len(buf) > 8:
                    continue
                for msg in msgs:
                    reply = self._dispatch(msg)
                    if reply:
                        conn.sendall(frame(reply))
        except OSError:
            pass
        finally:
            conn.close()

    def _dispatch(self, msg: bytes) -> bytes:
        if len(msg) < 64 or msg[:4] != SMB2:
            return b''
        command, message_id = struct.unpack_from('<H', msg, 12)[0], struct.unpack_from('<Q', msg, 24)[0]
        session_id = int.from_bytes(msg[40:48], 'little')
        tree_id = struct.unpack_from('<I', msg, 36)[0]
        body = msg[64:]
        if command == 0:
            return self._negotiate(message_id)
        if command == 1:
            return self._session(message_id)
        if command == 3:
            return self._tree(message_id, session_id)
        if command == 5:
            return self._create(message_id, session_id, tree_id, body)
        if command == 9:
            return self._write(message_id, session_id, tree_id, body)
        if command == 8:
            return self._read(message_id, session_id, tree_id, body)
        if command == 6:
            return _hdr(6, message_id, session_id, tree_id) + struct.pack('<H', 60) + b'\x00' * 58
        return _hdr(command, message_id, session_id, tree_id, status=0xC0000002)

    def _negotiate(self, message_id):
        guid = uuid.uuid4().bytes
        resp = struct.pack('<HHH2s16sIIIIQQHH',
                            65, 1, DIALECT, b'\x00\x00', guid,
                            0, 65536, 65536, 65536, 0, 0, 128, 0)
        return _hdr(0, message_id) + resp + b'\x00'

    def _session(self, message_id):
        sid = 0x1000
        resp = struct.pack('<HHH', 9, 0, 72) + b'\x00'
        return _hdr(1, message_id, session_id=sid) + resp

    def _tree(self, message_id, session_id):
        resp = struct.pack('<HBBI I', 16, 1, 0, 0, 0x001F01FF)
        return _hdr(3, message_id, session_id, tree_id=1) + resp

    def _create(self, message_id, session_id, tree_id, body):
        name_off, name_len = struct.unpack_from('<HH', body, 44)
        # offsets in CREATE are from the start of the SMB2 header
        raw = body[name_off - 64:name_off - 64 + name_len] if name_off >= 64 else b''
        name = raw.decode('utf-16le', errors='ignore').lower()
        fid = FILE_RESP if 'resp' in name else FILE_REQ
        file_id = fid.to_bytes(16, 'little')
        resp = struct.pack('<HBB', 89, 0, 0) + b'\x00' * 16 + b'\x00' * 32 + file_id + struct.pack('<II', 0, 0)
        # 89-byte structure: 2+1+1+4+8+8+4+8+8+4+4+16+4+4 = 88, plus 1? Spec is 89 including StructureSize.
        # Rebuild to 88 bytes after StructureSize field included in the pack above incorrectly.
        resp = struct.pack('<HB', 89, 0) + b'\x00' * 52 + file_id + b'\x00' * 16
        return _hdr(5, message_id, session_id, tree_id) + resp[:89]

    def _write(self, message_id, session_id, tree_id, body):
        data_off, length = struct.unpack_from('<HI', body, 2)
        fid = int.from_bytes(body[16:32], 'little') & 0xFF
        data = body[data_off - 64:data_off - 64 + length]
        self.files[fid] = data
        if fid == FILE_REQ and data:
            try:
                reply = self.handler(data, 'smb')
            except Exception:
                reply = b''
            self.files[FILE_RESP] = reply
        resp = struct.pack('<HHI', 17, 0, length) + b'\x00' * 4
        return _hdr(9, message_id, session_id, tree_id) + resp

    def _read(self, message_id, session_id, tree_id, body):
        length = struct.unpack_from('<I', body, 4)[0]
        fid = int.from_bytes(body[16:32], 'little') & 0xFF
        blob = self.files.get(fid, b'')[:length]
        data_off = 80
        resp = struct.pack('<HHII', 17, data_off, len(blob), 0) + b'\x00' * 4 + blob
        return _hdr(8, message_id, session_id, tree_id) + resp


def exchange(host: str, port: int, payload: bytes, timeout: float = 8) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        def rpc(body):
            sock.sendall(frame(body))
            buf = b''
            while True:
                buf += sock.recv(65536)
                msgs, buf = unframe(buf)
                if msgs:
                    return msgs[0]

        rpc(_hdr(0, 1) + struct.pack('<HHHHI16sQ', 36, 1, 1, 0, 0, b'\x11' * 16, 0) + struct.pack('<H', DIALECT))
        rpc(_hdr(1, 2) + struct.pack('<HBBIIHHQ', 25, 0, 0, 0, 0, 88, 1, 0) + b'\x00')
        rpc(_hdr(3, 3, session_id=0x1000) + struct.pack('<HHH', 9, 72, 8) + 'C2'.encode('utf-16le'))
        name = 'req'.encode('utf-16le')
        create = bytearray(64)
        struct.pack_into('<H', create, 0, 57)
        struct.pack_into('<HH', create, 44, 64 + 64, len(name))
        create = bytes(create) + name
        rpc(_hdr(5, 4, session_id=0x1000, tree_id=1) + create)
        data_off = 64 + 48
        write = bytearray(48) + payload
        struct.pack_into('<H', write, 0, 49)
        struct.pack_into('<H', write, 2, data_off)
        struct.pack_into('<I', write, 4, len(payload))
        write[16:32] = FILE_REQ.to_bytes(16, 'little')
        rpc(_hdr(9, 5, session_id=0x1000, tree_id=1) + bytes(write))
        read = bytearray(49)
        struct.pack_into('<H', read, 0, 49)
        struct.pack_into('<I', read, 4, 1024 * 1024)
        read[16:32] = FILE_RESP.to_bytes(16, 'little')
        reply = rpc(_hdr(8, 6, session_id=0x1000, tree_id=1) + bytes(read))
        data_off, length = struct.unpack_from('<HI', reply, 64 + 2)
        return reply[data_off:data_off + length]
    finally:
        sock.close()
