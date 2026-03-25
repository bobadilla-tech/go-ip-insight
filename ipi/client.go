// Package ipi provides IP address intelligence: VPN, proxy, Tor exit-node,
// and hosting-provider detection backed by a local IP2Proxy database.
//
// # Quickstart
//
//	client, err := ipi.New(ipi.WithDatabasePath("/path/to/IP2PROXY-LITE-PX2.BIN"))
//	if err != nil { ... }
//	defer client.Close()
//
//	result, err := client.CheckString(ctx, "1.2.3.4")
//
// # Database
//
// This package requires a local IP2Proxy .BIN database file. The free LITE
// tier (PX2) is sufficient for VPN, proxy, Tor, and hosting detection.
// Download it from https://lite.ip2location.com after free registration.
// The database is updated monthly; schedule a periodic download to keep
// detection coverage current.
//
// # Performance
//
// [Client] is safe for concurrent use across goroutines. For high-throughput
// services, consider wrapping [Client.Check] or [Client.CheckString] with an
// external LRU cache keyed by the IP string to avoid redundant database and
// DNS lookups for recently seen addresses.
//
// # Coverage
//
// VPN, proxy, and hosting detection rely on the IP2Proxy database, which may
// not cover every provider. Tor exit-node detection combines the database with
// a real-time DNS check against the Tor Project's DNSBL
// (dnsel.torproject.org), providing authoritative and frequently updated
// coverage for IPv4 addresses. IPv6 Tor exit nodes are detected via the
// database only, as the Tor Project's DNSBL does not support IPv6.
package ipi

import (
	"context"
	"fmt"
	"net"

	"github.com/ip2location/ip2proxy-go/v4"
)

// Client performs IP intelligence lookups against a local IP2Proxy database.
// A single Client is safe for concurrent use across goroutines.
type Client struct {
	db          *ip2proxy.DB
	torDNSCheck bool
}

type config struct {
	databasePath string
	torDNSCheck  bool
}

// Option configures a [Client].
type Option func(*config)

// WithDatabasePath sets the path to the IP2Proxy .BIN database file.
// This option is required; [New] returns an error if it is not provided.
func WithDatabasePath(path string) Option {
	return func(c *config) {
		c.databasePath = path
	}
}

// WithTorDNSCheck enables or disables the real-time Tor exit-node DNS check
// against the Tor Project's official DNSBL (dnsel.torproject.org).
//
// Enabled by default. Requires outbound DNS resolution. Disable when the
// service must operate without any external network access; detection will
// then rely solely on the IP2Proxy database.
func WithTorDNSCheck(enabled bool) Option {
	return func(c *config) {
		c.torDNSCheck = enabled
	}
}

// New creates a new Client using the provided options.
// [WithDatabasePath] is required.
func New(opts ...Option) (*Client, error) {
	cfg := &config{torDNSCheck: true}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.databasePath == "" {
		return nil, fmt.Errorf("ipi: database path is required; use WithDatabasePath")
	}

	db, err := ip2proxy.OpenDB(cfg.databasePath)
	if err != nil {
		return nil, fmt.Errorf("ipi: open database: %w", err)
	}

	return &Client{db: db, torDNSCheck: cfg.torDNSCheck}, nil
}

// Close releases the database file handle held by the Client.
// It should be called when the Client is no longer needed.
func (c *Client) Close() {
	c.db.Close()
}

// Check analyses ip and returns the full intelligence result.
//
// Private and reserved addresses (loopback, RFC 1918, link-local, etc.)
// return immediately with a zero [Result] and [ThreatNone] — no database or
// DNS lookups are performed.
//
// The context is forwarded to the Tor DNS check and can be used for
// cancellation and deadline control.
func (c *Client) Check(ctx context.Context, ip net.IP) (*Result, error) {
	if ip == nil {
		return nil, fmt.Errorf("ipi: nil IP address")
	}

	normalized := ip.To16()
	if normalized == nil {
		return nil, fmt.Errorf("ipi: invalid IP address")
	}

	if isPrivate(normalized) {
		return &Result{IP: normalized, Threat: ThreatNone}, nil
	}

	rec, err := lookupIP(c.db, normalized)
	if err != nil {
		return nil, err
	}

	result := &Result{
		IP:         normalized,
		IsVPN:      rec.IsVPN,
		IsProxy:    rec.IsProxy,
		IsTor:      rec.IsTor,
		IsHosting:  rec.IsHosting,
		FraudScore: rec.FraudScore,
	}

	if c.torDNSCheck && !result.IsTor {
		detected, dnsErr := isTorExitNode(ctx, normalized)
		if dnsErr == nil {
			result.IsTor = detected
		}
		// DNS errors are intentionally swallowed: the database result stands.
	}

	computeThreat(result)
	return result, nil
}

// CheckString parses ipStr as an IP address and calls [Client.Check].
// It returns an error if ipStr is not a valid IPv4 or IPv6 address.
func (c *Client) CheckString(ctx context.Context, ipStr string) (*Result, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("ipi: %q is not a valid IP address", ipStr)
	}
	return c.Check(ctx, ip)
}
