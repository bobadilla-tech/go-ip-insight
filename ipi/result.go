package ipi

import "fmt"

// ThreatLevel represents the assessed threat level of an IP address.
type ThreatLevel int

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

// String returns a human-readable name for the threat level.
func (t ThreatLevel) String() string {
	switch t {
	case ThreatNone:
		return "None"
	case ThreatLow:
		return "Low"
	case ThreatMedium:
		return "Medium"
	case ThreatHigh:
		return "High"
	case ThreatCritical:
		return "Critical"
	default:
		return fmt.Sprintf("ThreatLevel(%d)", int(t))
	}
}

// Result holds the intelligence findings for a given IP address.
type Result struct {
	// IP is the analysed address in its 16-byte (net.IP) form.
	IP []byte

	// IsVPN is true when the address belongs to a known VPN provider.
	IsVPN bool

	// IsProxy is true when the address is a known public or web proxy.
	IsProxy bool

	// IsTor is true when the address is a known Tor exit node,
	// detected via the IP2Proxy database or the Tor Project's DNSBL.
	IsTor bool

	// IsHosting is true when the address belongs to a data-centre or hosting
	// provider range (DCH in IP2Proxy terminology).
	IsHosting bool

	// Score is the raw threat score used to derive Threat.
	//
	//   Flag     Points
	//   ──────────────
	//   Tor        3
	//   VPN        2
	//   Proxy      2
	//   Hosting    1
	Score int

	// Threat is the threat level derived from Score.
	//
	//   Score  Level
	//   ─────────────
	//   0      None
	//   1      Low
	//   2–3    Medium
	//   4–5    High
	//   ≥6     Critical
	Threat ThreatLevel

	// FraudScore is populated when using an IP2Proxy database of tier PX5 or
	// higher. It ranges from 0 (no fraud risk) to 100 (high fraud risk).
	// Zero means the value is unavailable for the current database tier.
	FraudScore int

	// AsnOrg is the name of the organisation that owns the Autonomous System
	// containing the address, as reported by the MaxMind GeoLite2-ASN database
	// (e.g. "DIGITALOCEAN-ASN"). Empty when the ASN lookup returns no record.
	AsnOrg string

	// AsnNumber is the Autonomous System Number for the address (e.g. 15169).
	// Zero when the ASN lookup returns no record.
	AsnNumber uint

	// AsnRoute is the announced network prefix containing the address in CIDR
	// notation (e.g. "8.8.8.0/24"). Empty when the ASN lookup returns no record.
	AsnRoute string

	// Country is the full English country name for the address
	// (e.g. "United States"), as reported by the MaxMind GeoLite2-City database.
	Country string

	// CountryCode is the ISO 3166-1 alpha-2 country code (e.g. "US").
	CountryCode string

	// City is the English city name for the address (e.g. "Mountain View").
	// Empty for addresses where city-level data is unavailable.
	City string
}

// ASNInfo holds structured ASN and network information for a given IP address.
// It is returned by [Client.CheckASN] and is suitable for direct use in
// API responses.
type ASNInfo struct {
	// IP is the queried address in string form.
	IP string

	// ASN is the Autonomous System Number formatted with an "AS" prefix
	// (e.g. "AS15169"). Empty when no record is found.
	ASN string

	// Org is the organisation name registered for the ASN
	// (e.g. "Google LLC").
	Org string

	// ISP is the Internet Service Provider name. With the GeoLite2-ASN free
	// tier this is identical to Org; a paid MaxMind ISP database would provide
	// a distinct value.
	ISP string

	// Domain is the primary domain associated with the ASN
	// (e.g. "google.com"). Always empty with the GeoLite2-ASN free tier;
	// requires a paid MaxMind domain database.
	Domain string

	// Route is the announced network prefix in CIDR notation
	// (e.g. "8.8.8.0/24").
	Route string

	// Type classifies the network based on available signals:
	//   "hosting"     — data-centre or cloud provider
	//   "vpn"         — VPN provider (not hosting)
	//   "proxy"       — public or web proxy (not hosting or VPN)
	//   "residential" — none of the above
	Type string
}

// Threat scoring weights.
const (
	weightTor     = 3
	weightVPN     = 2
	weightProxy   = 2
	weightHosting = 1
)

// computeThreat calculates Score and Threat for r in place.
func computeThreat(r *Result) {
	s := 0
	if r.IsTor {
		s += weightTor
	}
	if r.IsVPN {
		s += weightVPN
	}
	if r.IsProxy {
		s += weightProxy
	}
	if r.IsHosting {
		s += weightHosting
	}
	r.Score = s
	switch {
	case s == 0:
		r.Threat = ThreatNone
	case s == 1:
		r.Threat = ThreatLow
	case s <= 3:
		r.Threat = ThreatMedium
	case s <= 5:
		r.Threat = ThreatHigh
	default:
		r.Threat = ThreatCritical
	}
}
