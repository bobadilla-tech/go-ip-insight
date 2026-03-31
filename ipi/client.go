// Package ipi provides IP address intelligence: VPN, proxy, Tor exit-node,
// hosting-provider detection, ASN lookup, and geolocation, backed by three
// local databases.
//
// # Quickstart
//
//	client, err := ipi.New(
//	    ipi.WithDatabasePath("/path/to/IP2PROXY-LITE-PX2.BIN"),
//	    ipi.WithASNDatabasePath("/path/to/GeoLite2-ASN.mmdb"),
//	    ipi.WithCityDatabasePath("/path/to/GeoLite2-City.mmdb"),
//	)
//	if err != nil { ... }
//	defer client.Close()
//
//	result, err := client.CheckString(ctx, "1.2.3.4")
//
//	asnInfo, err := client.CheckASNString(ctx, "1.2.3.4")
//
// # Databases
//
// Three local database files are required:
//
//   - IP2Proxy .BIN — primary source for VPN, proxy, Tor, and hosting
//     detection. The free LITE tier (PX2) is sufficient. Download from
//     https://lite.ip2location.com after free registration.
//
//   - MaxMind GeoLite2-ASN .mmdb — ASN lookup: number, organisation name,
//     announced network prefix, and secondary hosting detection via a curated
//     ASN list. Download from
//     https://dev.maxmind.com/geoip/geolite2-free-geolocation-data after free
//     registration. Updated weekly.
//
//   - MaxMind GeoLite2-City .mmdb — geolocation: country, country code, and
//     city. Same download location as GeoLite2-ASN. Updated weekly.
//
// All databases are read into memory at startup; no file I/O occurs at query
// time.
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
// VPN, proxy, and Tor detection rely primarily on the IP2Proxy database.
// Hosting detection is the union of both sources: an address is flagged
// IsHosting when either IP2Proxy classifies it as DCH or its ASN appears in
// the curated hosting ASN list. Tor exit-node detection additionally performs
// a real-time DNS check against the Tor Project's DNSBL
// (dnsel.torproject.org) for IPv4 addresses.
package ipi

import (
	"context"
	"fmt"
	"net"

	"github.com/ip2location/ip2proxy-go/v4"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

// Client performs IP intelligence lookups against a local IP2Proxy database,
// a local MaxMind GeoLite2-ASN database, and a local MaxMind GeoLite2-City
// database. A single Client is safe for concurrent use across goroutines.
type Client struct {
	proxyDB     *ip2proxy.DB
	asnDB       *maxminddb.Reader
	cityDB      *geoip2.Reader
	torDNSCheck bool
}

type config struct {
	databasePath     string
	asnDatabasePath  string
	cityDatabasePath string
	torDNSCheck      bool
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

// WithASNDatabasePath sets the path to the MaxMind GeoLite2-ASN .mmdb file.
// This option is required; [New] returns an error if it is not provided.
func WithASNDatabasePath(path string) Option {
	return func(c *config) {
		c.asnDatabasePath = path
	}
}

// WithCityDatabasePath sets the path to the MaxMind GeoLite2-City .mmdb file.
// This option is required; [New] returns an error if it is not provided.
func WithCityDatabasePath(path string) Option {
	return func(c *config) {
		c.cityDatabasePath = path
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
// [WithDatabasePath], [WithASNDatabasePath], and [WithCityDatabasePath] are
// all required.
func New(opts ...Option) (*Client, error) {
	cfg := &config{torDNSCheck: true}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.databasePath == "" {
		return nil, fmt.Errorf("ipi: IP2Proxy database path is required; use WithDatabasePath")
	}
	if cfg.asnDatabasePath == "" {
		return nil, fmt.Errorf("ipi: ASN database path is required; use WithASNDatabasePath")
	}
	if cfg.cityDatabasePath == "" {
		return nil, fmt.Errorf("ipi: city database path is required; use WithCityDatabasePath")
	}

	proxyDB, err := ip2proxy.OpenDB(cfg.databasePath)
	if err != nil {
		return nil, fmt.Errorf("ipi: open IP2Proxy database: %w", err)
	}

	asnDB, err := maxminddb.Open(cfg.asnDatabasePath)
	if err != nil {
		proxyDB.Close()
		return nil, fmt.Errorf("ipi: open ASN database: %w", err)
	}

	cityDB, err := geoip2.Open(cfg.cityDatabasePath)
	if err != nil {
		proxyDB.Close()
		asnDB.Close()
		return nil, fmt.Errorf("ipi: open city database: %w", err)
	}

	return &Client{
		proxyDB:     proxyDB,
		asnDB:       asnDB,
		cityDB:      cityDB,
		torDNSCheck: cfg.torDNSCheck,
	}, nil
}

// Close releases the file handles held by all databases.
// It should be called when the Client is no longer needed.
func (c *Client) Close() {
	c.proxyDB.Close()
	c.asnDB.Close()
	c.cityDB.Close()
}

// Check analyses ip and returns the full intelligence result.
//
// Detection signals are sourced from all three databases and merged:
//   - IsVPN, IsProxy, IsTor: IP2Proxy only.
//   - IsHosting: true when either IP2Proxy classifies the address as DCH or
//     the address's ASN is in the curated hosting provider list.
//   - AsnOrg, AsnNumber, AsnRoute: MaxMind GeoLite2-ASN.
//   - Country, CountryCode, City: MaxMind GeoLite2-City.
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

	proxyRec, err := lookupProxy(c.proxyDB, normalized)
	if err != nil {
		return nil, err
	}

	asnRec, err := lookupASN(c.asnDB, normalized)
	if err != nil {
		return nil, err
	}

	cityRec, err := lookupCity(c.cityDB, normalized)
	if err != nil {
		return nil, err
	}

	result := &Result{
		IP:          normalized,
		IsVPN:       proxyRec.IsVPN,
		IsProxy:     proxyRec.IsProxy,
		IsTor:       proxyRec.IsTor,
		IsHosting:   proxyRec.IsHosting || asnRec.IsHosting,
		FraudScore:  proxyRec.FraudScore,
		AsnOrg:      asnRec.AsnOrg,
		AsnNumber:   asnRec.AsnNumber,
		AsnRoute:    asnRec.AsnRoute,
		Country:     cityRec.Country,
		CountryCode: cityRec.CountryCode,
		City:        cityRec.City,
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

// CheckASN returns structured ASN and network information for ip.
//
// Unlike [Client.Check], this method focuses solely on ASN data and network
// type classification. It is intended for use in dedicated ASN lookup
// endpoints. Private and reserved addresses return an error — they have no
// meaningful public ASN.
//
// The returned [ASNInfo].Type is derived from proxy and ASN signals:
// "hosting", "vpn", "proxy", or "residential".
func (c *Client) CheckASN(ctx context.Context, ip net.IP) (*ASNInfo, error) {
	if ip == nil {
		return nil, fmt.Errorf("ipi: nil IP address")
	}

	normalized := ip.To16()
	if normalized == nil {
		return nil, fmt.Errorf("ipi: invalid IP address")
	}

	if isPrivate(normalized) {
		return nil, fmt.Errorf("ipi: %s is a private/reserved address; no public ASN available", net.IP(normalized))
	}

	asnRec, err := lookupASN(c.asnDB, normalized)
	if err != nil {
		return nil, err
	}

	proxyRec, err := lookupProxy(c.proxyDB, normalized)
	if err != nil {
		return nil, err
	}

	asn := ""
	if asnRec.AsnNumber != 0 {
		asn = fmt.Sprintf("AS%d", asnRec.AsnNumber)
	}

	isHosting := asnRec.IsHosting || proxyRec.IsHosting
	return &ASNInfo{
		IP:     net.IP(normalized).String(),
		ASN:    asn,
		Org:    asnRec.AsnOrg,
		ISP:    asnRec.AsnOrg,
		Domain: "",
		Route:  asnRec.AsnRoute,
		Type:   asnType(isHosting, proxyRec.IsVPN, proxyRec.IsProxy),
	}, nil
}

// CheckASNString parses ipStr as an IP address and calls [Client.CheckASN].
// It returns an error if ipStr is not a valid IPv4 or IPv6 address.
func (c *Client) CheckASNString(ctx context.Context, ipStr string) (*ASNInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("ipi: %q is not a valid IP address", ipStr)
	}
	return c.CheckASN(ctx, ip)
}
