package ipi

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ip2location/ip2proxy-go/v4"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

// ---- IP2Proxy ---------------------------------------------------------------

// proxyRecord is an internal representation of an IP2Proxy lookup result,
// containing only the fields relevant to this package.
type proxyRecord struct {
	IsVPN      bool
	IsProxy    bool
	IsTor      bool
	IsHosting  bool
	FraudScore int
}

// lookupProxy queries the IP2Proxy database for ip and maps the result to a
// proxyRecord.
//
// IP2Proxy proxy type mapping:
//   - VPN  → IsVPN
//   - TOR  → IsTor
//   - DCH  → IsHosting (data centre / hosting provider)
//   - PUB  → IsProxy   (public proxy)
//   - WEB  → IsProxy   (web proxy)
//   - RES  → IsProxy   (residential proxy, PX10+ tiers)
//   - SES  → no flag   (search engine spider, not a threat)
//   - "-"  → no flag   (not a proxy)
func lookupProxy(db *ip2proxy.DB, ip net.IP) (proxyRecord, error) {
	rec, err := db.GetAll(ip.String())
	if err != nil {
		return proxyRecord{}, fmt.Errorf("ip2proxy lookup: %w", err)
	}

	fraudScore, _ := strconv.Atoi(rec.FraudScore)
	result := proxyRecord{FraudScore: fraudScore}

	// IsProxy == -1: field not supported by the current database tier.
	// IsProxy ==  0: not a proxy.
	// IsProxy ==  1: proxy detected.
	if rec.IsProxy != 1 {
		return result, nil
	}

	switch rec.ProxyType {
	case "VPN":
		result.IsVPN = true
	case "TOR":
		result.IsTor = true
	case "DCH":
		result.IsHosting = true
	case "PUB", "WEB", "RES":
		result.IsProxy = true
	case "SES", "-":
		// Search engine spider or no value: not treated as a threat.
	default:
		// Unknown type: treat conservatively as a generic proxy.
		result.IsProxy = true
	}

	return result, nil
}

// ---- MaxMind GeoLite2-ASN ---------------------------------------------------

// asnRecord is an internal representation of a GeoLite2-ASN lookup result.
type asnRecord struct {
	IsHosting bool
	AsnOrg    string
	AsnNumber uint
	AsnRoute  string
}

// hostingASNs is a curated set of Autonomous System Numbers belonging to
// known hosting, cloud, and CDN providers.
//
// This list covers the most widely encountered providers. It is intentionally
// conservative — only ASNs with clear hosting intent are included. New
// providers or ASN reassignments may not be present until the list is updated.
var hostingASNs = map[uint]struct{}{
	// Amazon Web Services
	14618: {}, 16509: {},
	// Google Cloud / GCP
	15169: {}, 396982: {},
	// Microsoft Azure
	3598: {}, 8068: {}, 8069: {}, 8070: {}, 8075: {},
	// Alibaba Cloud
	37963: {}, 45102: {},
	// Oracle Cloud Infrastructure
	31898: {}, 202468: {},
	// IBM Cloud / SoftLayer
	36351: {},
	// DigitalOcean
	14061: {},
	// Linode / Akamai Cloud Compute
	63949: {},
	// Vultr
	20473: {},
	// Hetzner Online
	24940: {},
	// OVH
	16276: {},
	// Scaleway
	12876: {},
	// Contabo
	51167: {},
	// Leaseweb
	28753: {},
	// IONOS / 1&1
	8560: {},
	// Rackspace
	27357: {}, 33070: {},
	// Cloudflare
	13335: {},
	// Fastly
	54113: {},
	// Akamai Technologies
	20940: {},
	// Hurricane Electric
	6939: {},
	// Zayo Group
	6461: {},
	// Cogent Communications
	174: {},
	// NFOrce Entertainment
	43350: {},
	// Psychz Networks
	40676: {},
	// Sharktech
	23367: {},
	// FranTech Solutions / BuyVM
	53667: {},
}

// rawASNRecord mirrors the fields stored in the GeoLite2-ASN mmdb file.
type rawASNRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// lookupASN queries the GeoLite2-ASN database for ip using the low-level
// maxminddb reader so that the announced network prefix (route) is also
// available. IsHosting is set when the IP's ASN is in the curated hostingASNs
// list.
func lookupASN(db *maxminddb.Reader, ip net.IP) (asnRecord, error) {
	var raw rawASNRecord
	network, ok, err := db.LookupNetwork(ip, &raw)
	if err != nil {
		return asnRecord{}, fmt.Errorf("maxmind ASN lookup: %w", err)
	}

	if !ok {
		return asnRecord{}, nil
	}

	route := ""
	if network != nil {
		route = network.String()
	}

	_, isHosting := hostingASNs[raw.AutonomousSystemNumber]
	return asnRecord{
		IsHosting: isHosting,
		AsnOrg:    raw.AutonomousSystemOrganization,
		AsnNumber: raw.AutonomousSystemNumber,
		AsnRoute:  route,
	}, nil
}

// ---- MaxMind GeoLite2-City --------------------------------------------------

// cityRecord is an internal representation of a GeoLite2-City lookup result.
type cityRecord struct {
	Country     string
	CountryCode string
	City        string
}

// lookupCity queries the GeoLite2-City database for ip and returns the
// country and city fields in English.
func lookupCity(db *geoip2.Reader, ip net.IP) (cityRecord, error) {
	rec, err := db.City(ip)
	if err != nil {
		return cityRecord{}, fmt.Errorf("maxmind city lookup: %w", err)
	}

	city := rec.City.Names["en"]
	return cityRecord{
		Country:     rec.Country.Names["en"],
		CountryCode: rec.Country.IsoCode,
		City:        city,
	}, nil
}

// ---- Helpers ----------------------------------------------------------------

// asnType derives a network type string from the detection signals.
// Priority: hosting > vpn > proxy > residential.
func asnType(isHosting, isVPN, isProxy bool) string {
	switch {
	case isHosting:
		return "hosting"
	case isVPN:
		return "vpn"
	case isProxy:
		return "proxy"
	default:
		return "residential"
	}
}
