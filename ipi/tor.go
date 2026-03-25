package ipi

import (
	"context"
	"fmt"
	"net"
	"slices"
)

// isTorExitNode queries the Tor Project's DNSBL to check whether ip is a
// known Tor exit node.
//
// It reverses the IPv4 octets and resolves
// <d>.<c>.<b>.<a>.dnsel.torproject.org. A response of 127.0.0.2 confirms
// the address is a Tor exit node.
//
// IPv6 addresses are not supported by dnsel.torproject.org. Pure IPv6 Tor
// exit nodes are detected via the IP2Proxy database only.
//
// NXDOMAIN responses return (false, nil). Other DNS errors are returned to
// the caller.
func isTorExitNode(ctx context.Context, ip net.IP) (bool, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		// dnsel.torproject.org does not support IPv6.
		return false, nil
	}

	// Reverse the octets: a.b.c.d → d.c.b.a.dnsel.torproject.org.
	host := fmt.Sprintf("%d.%d.%d.%d.dnsel.torproject.org.", ip4[3], ip4[2], ip4[1], ip4[0])

	var r net.Resolver
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		if isNXDomain(err) {
			return false, nil
		}
		return false, fmt.Errorf("tor DNS check: %w", err)
	}

	if slices.Contains(addrs, "127.0.0.2") {
		return true, nil
	}
	return false, nil
}

func isNXDomain(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && dnsErr.IsNotFound
}
