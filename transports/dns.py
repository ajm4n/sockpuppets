"""DNS transport. Payload rides in a TXT additional record; the reply is a TXT answer."""

import socket
import struct
import threading


def _name(labels):
    out = b''
    for label in labels:
        raw = label.encode() if isinstance(label, str) else label
        out += bytes([len(raw)]) + raw
    return out + b'\x00'


def _parse_name(data, offset):
    labels = []
    jumped = False
    start = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                start = offset + 2
            offset = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length])
        offset += length
    return labels, (start if jumped else offset)


def _txt(blob: bytes) -> bytes:
    out = b''
    for i in range(0, len(blob), 255):
        chunk = blob[i:i + 255]
        out += bytes([len(chunk)]) + chunk
    return out or b'\x00'


def _untxt(rdata: bytes) -> bytes:
    out = b''
    i = 0
    while i < len(rdata):
        n = rdata[i]
        i += 1
        out += rdata[i:i + n]
        i += n
    return out


def build_query(payload: bytes, qid: int = 1) -> bytes:
    header = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 1)
    question = _name(['c2']) + struct.pack('!HH', 16, 1)
    additional = _name(['p']) + struct.pack('!HHIH', 16, 1, 0, len(_txt(payload))) + _txt(payload)
    return header + question + additional


def parse_response(packet: bytes) -> bytes:
    if len(packet) < 12:
        raise ValueError('short dns packet')
    qd, an = struct.unpack('!HH', packet[4:8])
    offset = 12
    for _ in range(qd):
        _, offset = _parse_name(packet, offset)
        offset += 4
    for _ in range(an):
        _, offset = _parse_name(packet, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        if rtype == 16:
            return _untxt(rdata)
    raise ValueError('no txt answer')


def exchange(host: str, port: int, payload: bytes, timeout: float = 8) -> bytes:
    query = build_query(payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return parse_response(data)


class DNSServer:
    def __init__(self, host, port, handler):
        self.host = host
        self.port = port
        self.handler = handler
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            try:
                reply = self._handle(data)
                self._sock.sendto(reply, addr)
            except Exception:
                continue

    def _handle(self, data: bytes) -> bytes:
        qid = struct.unpack('!H', data[:2])[0]
        qd, an, ns, ar = struct.unpack('!HHHH', data[4:12])
        offset = 12
        for _ in range(qd):
            _, offset = _parse_name(data, offset)
            offset += 4
        for _ in range(an + ns):
            _, offset = _parse_name(data, offset)
            offset += 8
            rdlen = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2 + rdlen
        payload = b''
        if ar:
            _, offset = _parse_name(data, offset)
            rtype, _, _, rdlen = struct.unpack('!HHIH', data[offset:offset + 10])
            rdata = data[offset + 10:offset + 10 + rdlen]
            if rtype == 16:
                payload = _untxt(rdata)
        response = self.handler(payload, 'dns') if payload else b''
        txt = _txt(response)
        header = struct.pack('!HHHHHH', qid, 0x8400, 1, 1, 0, 0)
        question = _name(['c2']) + struct.pack('!HH', 16, 1)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 30, len(txt)) + txt
        return header + question + answer
