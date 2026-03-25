package ipi

import "net"

// privateRanges4 lists RFC-reserved IPv4 CIDR blocks that should never be
// looked up in an external database.
var privateRanges4 = mustParseCIDRs([]string{
	"10.0.0.0/8",       // RFC 1918 – private
	"172.16.0.0/12",    // RFC 1918 – private
	"192.168.0.0/16",   // RFC 1918 – private
	"127.0.0.0/8",      // Loopback
	"169.254.0.0/16",   // Link-local (RFC 3927)
	"100.64.0.0/10",    // CGNAT (RFC 6598)
	"192.0.2.0/24",     // TEST-NET-1 (RFC 5737)
	"198.51.100.0/24",  // TEST-NET-2 (RFC 5737)
	"203.0.113.0/24",   // TEST-NET-3 (RFC 5737)
	"0.0.0.0/8",        // This network (RFC 1122)
	"240.0.0.0/4",      // Reserved (RFC 1112)
	"255.255.255.255/32", // Limited broadcast
})

// privateRanges6 lists RFC-reserved IPv6 CIDR blocks.
var privateRanges6 = mustParseCIDRs([]string{
	"::1/128",        // Loopback (RFC 4291)
	"fc00::/7",       // Unique local (RFC 4193)
	"fe80::/10",      // Link-local (RFC 4291)
	"2001:db8::/32",  // Documentation (RFC 3849)
	"100::/64",       // Discard prefix (RFC 6666)
	"::/128",         // Unspecified address
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("ipi: invalid built-in CIDR " + c + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}

// isPrivate returns true when ip is a loopback, private, or reserved address.
// It handles both native IPv4 and IPv4-mapped IPv6 addresses transparently.
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		for _, r := range privateRanges4 {
			if r.Contains(ip4) {
				return true
			}
		}
		return false
	}
	for _, r := range privateRanges6 {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
