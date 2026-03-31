package ipi

import (
	"net"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	private := []string{
		// RFC 1918
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.255.255",
		// Loopback
		"127.0.0.1",
		"127.255.255.255",
		// Link-local
		"169.254.0.1",
		"169.254.255.255",
		// CGNAT (RFC 6598)
		"100.64.0.1",
		"100.127.255.255",
		// Test nets (RFC 5737)
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
		// This network / reserved
		"0.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		// IPv6 loopback
		"::1",
		// IPv6 unique local
		"fc00::1",
		"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		// IPv6 link-local
		"fe80::1",
		// IPv6 documentation
		"2001:db8::1",
		// IPv4-mapped loopback
		"::ffff:127.0.0.1",
	}

	public := []string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"1.0.0.1",
		"208.67.222.222",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
	}

	for _, ipStr := range private {
		ip := net.ParseIP(ipStr).To16()
		if ip == nil {
			t.Fatalf("failed to parse %q", ipStr)
		}
		if !isPrivate(ip) {
			t.Errorf("isPrivate(%q) = false, want true", ipStr)
		}
	}

	for _, ipStr := range public {
		ip := net.ParseIP(ipStr).To16()
		if ip == nil {
			t.Fatalf("failed to parse %q", ipStr)
		}
		if isPrivate(ip) {
			t.Errorf("isPrivate(%q) = true, want false", ipStr)
		}
	}
}
