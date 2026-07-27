package main

import (
	"net"
	"os"
	"regexp"
	"strings"
)

// Build-time configuration for environment validation
var (
	configSysHostname = ""
	configSysDomain   = ""
	configSysMAC      = ""
	configSysRegistry = ""
	configSysString   = ""
)

// validateEnvironment checks that the runtime environment matches
// the expected configuration. Returns true if all configured checks
// pass (unconfigured checks are skipped). Returns false if any check fails.
func validateEnvironment() bool {
	if configSysHostname != "" && !matchHostname(configSysHostname) {
		return false
	}
	if configSysDomain != "" && !matchDomain(configSysDomain) {
		return false
	}
	if configSysMAC != "" && !matchMAC(configSysMAC) {
		return false
	}
	if configSysRegistry != "" && !matchRegistry(configSysRegistry) {
		return false
	}
	if configSysString != "" && !matchString(configSysString) {
		return false
	}
	return true
}

// matchHostname checks if the current hostname matches the expected value.
// Supports exact match (case-insensitive) or regex if the value starts with "~".
func matchHostname(expected string) bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	if strings.HasPrefix(expected, "~") {
		pattern := expected[1:]
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		return re.MatchString(hostname)
	}
	return strings.EqualFold(hostname, expected)
}

// matchDomain checks if the machine is joined to the expected domain.
// Checks USERDNSDOMAIN and USERDOMAIN environment variables, as well as
// the FQDN suffix from the hostname.
func matchDomain(expected string) bool {
	expected = strings.ToLower(expected)

	// Check Windows domain env vars
	for _, envVar := range []string{"USERDNSDOMAIN", "USERDOMAIN"} {
		val := os.Getenv(envVar)
		if val != "" && strings.EqualFold(val, expected) {
			return true
		}
	}

	// Check FQDN - hostname may contain domain suffix
	hostname, err := os.Hostname()
	if err == nil {
		addrs, err := net.LookupHost(hostname)
		if err == nil && len(addrs) > 0 {
			names, err := net.LookupAddr(addrs[0])
			if err == nil {
				for _, name := range names {
					name = strings.TrimSuffix(strings.ToLower(name), ".")
					if strings.Contains(name, ".") {
						// Extract domain portion (everything after first dot)
						parts := strings.SplitN(name, ".", 2)
						if len(parts) == 2 && strings.EqualFold(parts[1], expected) {
							return true
						}
					}
				}
			}
		}
	}

	// Check /etc/resolv.conf domain/search on Linux/macOS
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "domain ") || strings.HasPrefix(line, "search ") {
				fields := strings.Fields(line)
				for _, field := range fields[1:] {
					if strings.EqualFold(field, expected) {
						return true
					}
				}
			}
		}
	}

	return false
}

// matchMAC checks if any network interface has a MAC address starting
// with the given prefix (e.g., "00:50:56" for VMware).
// The comparison is case-insensitive and handles both ":" and "-" separators.
func matchMAC(prefix string) bool {
	prefix = strings.ToLower(strings.ReplaceAll(prefix, "-", ":"))

	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		if mac != "" && strings.HasPrefix(mac, prefix) {
			return true
		}
	}
	return false
}

// matchString checks for the presence of a specific string in the environment.
// If the value looks like a file path (starts with / or X:\), checks file existence.
// Otherwise checks all environment variable values for the string.
func matchString(value string) bool {
	// Check if it looks like a file path
	if strings.HasPrefix(value, "/") ||
		(len(value) >= 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/')) {
		_, err := os.Stat(value)
		return err == nil
	}

	// Check environment variables for the string
	for _, env := range os.Environ() {
		if strings.Contains(env, value) {
			return true
		}
	}
	return false
}
