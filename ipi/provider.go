package ipi

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ip2location/ip2proxy-go/v4"
)

// proxyRecord is an internal representation of an IP2Proxy lookup result,
// containing only the fields relevant to this package.
type proxyRecord struct {
	IsVPN      bool
	IsProxy    bool
	IsTor      bool
	IsHosting  bool
	FraudScore int
}

// lookupIP queries the IP2Proxy database for ip and maps the result to a
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
func lookupIP(db *ip2proxy.DB, ip net.IP) (proxyRecord, error) {
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
