package ipi

import (
	"fmt"
	"testing"
)

func TestAsnType(t *testing.T) {
	tests := []struct {
		isHosting bool
		isVPN     bool
		isProxy   bool
		want      string
	}{
		{false, false, false, "residential"},
		{true, false, false, "hosting"},
		{false, true, false, "vpn"},
		{false, false, true, "proxy"},
		// hosting takes priority over vpn and proxy
		{true, true, false, "hosting"},
		{true, false, true, "hosting"},
		{true, true, true, "hosting"},
		// vpn takes priority over proxy
		{false, true, true, "vpn"},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("hosting=%v vpn=%v proxy=%v", tc.isHosting, tc.isVPN, tc.isProxy)
		t.Run(name, func(t *testing.T) {
			got := asnType(tc.isHosting, tc.isVPN, tc.isProxy)
			if got != tc.want {
				t.Errorf("asnType(%v, %v, %v) = %q, want %q",
					tc.isHosting, tc.isVPN, tc.isProxy, got, tc.want)
			}
		})
	}
}

func TestASNFormatting(t *testing.T) {
	tests := []struct {
		number uint
		want   string
	}{
		{15169, "AS15169"},
		{13335, "AS13335"},
		{14061, "AS14061"},
		{1, "AS1"},
	}

	for _, tc := range tests {
		got := fmt.Sprintf("AS%d", tc.number)
		if got != tc.want {
			t.Errorf("AS%d = %q, want %q", tc.number, got, tc.want)
		}
	}
}

func TestHostingASNs(t *testing.T) {
	knownHosting := []uint{
		14618, 16509,   // AWS
		15169, 396982,  // Google Cloud
		8075,           // Microsoft Azure
		14061,          // DigitalOcean
		13335,          // Cloudflare
		24940,          // Hetzner
	}

	for _, asn := range knownHosting {
		if _, ok := hostingASNs[asn]; !ok {
			t.Errorf("ASN %d should be in hostingASNs", asn)
		}
	}

	notHosting := []uint{
		7922,  // Comcast
		701,   // Verizon
		3320,  // Deutsche Telekom
	}

	for _, asn := range notHosting {
		if _, ok := hostingASNs[asn]; ok {
			t.Errorf("ASN %d should NOT be in hostingASNs", asn)
		}
	}
}
