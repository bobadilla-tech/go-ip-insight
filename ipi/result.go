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
