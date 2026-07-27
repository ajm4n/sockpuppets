package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func hkdfSHA256(ikm, salt, info []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{1})
	return mac.Sum(nil)
}

var (
	wireSession []byte
	wireHS      []byte
	wireEph     *ecdh.PrivateKey
)

func wireSeal(key []byte, text string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, []byte(text), nil)...), nil
}

func wireOpen(key, blob []byte) (string, error) {
	if len(blob) < 12+16 {
		return "", fmt.Errorf("ciphertext rejected")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, blob[:12], blob[12:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func wireEncrypt(data string) (string, error) {
	if wireSession != nil {
		sealed, err := wireSeal(wireSession, data)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(append([]byte("AES1"), sealed...)), nil
	}
	pubRaw, err := hex.DecodeString(strings.TrimSpace(configServerPub))
	if err != nil || len(pubRaw) != 32 {
		return "", fmt.Errorf("missing server public key")
	}
	curve := ecdh.X25519()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	serverPub, err := curve.NewPublicKey(pubRaw)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(serverPub)
	if err != nil {
		return "", err
	}
	hs := hkdfSHA256(shared, []byte("sockpuppets-salt-v1"), []byte("sockpuppets-handshake-v1"))
	sealed, err := wireSeal(hs, data)
	if err != nil {
		return "", err
	}
	wireEph = eph
	wireHS = hs
	raw := append(eph.PublicKey().Bytes(), sealed...)
	return "EPH1." + base64.StdEncoding.EncodeToString(raw), nil
}

func wireDecrypt(encoded string) (string, error) {
	if strings.HasPrefix(encoded, "EPH2.") {
		raw, err := base64.StdEncoding.DecodeString(encoded[5:])
		if err != nil || len(raw) < 32 || wireEph == nil {
			return "", fmt.Errorf("bad welcome")
		}
		curve := ecdh.X25519()
		srvPub, err := curve.NewPublicKey(raw[:32])
		if err != nil {
			return "", err
		}
		pt, err := wireOpen(wireHS, raw[32:])
		if err != nil {
			return "", err
		}
		shared2, err := wireEph.ECDH(srvPub)
		if err != nil {
			return "", err
		}
		wireSession = hkdfSHA256(append(shared2, wireHS...), []byte("sockpuppets-salt-v1"), []byte("sockpuppets-session-v1"))
		wireEph = nil
		return pt, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 4 || string(raw[:4]) != "AES1" || wireSession == nil {
		return "", fmt.Errorf("ciphertext rejected")
	}
	return wireOpen(wireSession, raw[4:])
}
