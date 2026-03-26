# go-ip-intelligence

A Go package for IP address intelligence. Given any IPv4 or IPv6 address it
determines whether the address belongs to a VPN provider, a proxy (public or
web), a Tor exit node, or a hosting/data-centre range, and derives a
structured threat level from those signals.

Designed for embedding in backend services: the `Client` is safe for
concurrent use, all detection runs locally against two bundled binary
databases, and the public API is intentionally small.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Data sources](#data-sources)
- [Getting started](#getting-started)
- [API reference](#api-reference)
- [Threat scoring](#threat-scoring)
- [CLI tool](#cli-tool)
- [Tradeoffs](#tradeoffs)
- [Performance](#performance)
- [Known limitations](#known-limitations)
- [Possible improvements](#possible-improvements)

---

## Features

| Signal | Detection mechanism |
| --- | --- |
| VPN | IP2Proxy database (proxy type `VPN`) |
| Public / web proxy | IP2Proxy database (proxy types `PUB`, `WEB`, `RES`) |
| Tor exit node | IP2Proxy database **+** Tor Project DNSBL |
| Hosting / data centre | IP2Proxy database (`DCH`) **+** MaxMind GeoLite2-ASN (curated ASN list) |
| ASN organisation name | MaxMind GeoLite2-ASN database |
| Private / reserved IPs | Built-in RFC range check (no database I/O) |
| Threat level | Weighted score → `None / Low / Medium / High / Critical` |

---

## How it works

### 1. Private IP short-circuit

Before any lookup the package checks whether the address falls inside a
private or reserved range (RFC 1918, loopback, link-local, CGNAT, test nets,
etc.). If it does, the call returns immediately with `ThreatNone` and all
flags `false`. This avoids unnecessary work for addresses that will never
appear in a database and is the common case in services that also receive
internal traffic from load-balancers or health checks.

### 2. IP2Proxy database lookup

The address is looked up in the binary IP2Proxy database. The database assigns
each address a single primary **proxy type**:

| Type | Meaning | Flag set |
| --- | --- | --- |
| `VPN` | VPN anonymizer | `IsVPN` |
| `TOR` | Tor exit node | `IsTor` |
| `DCH` | Data centre / hosting range | `IsHosting` |
| `PUB` | Public proxy | `IsProxy` |
| `WEB` | Web proxy | `IsProxy` |
| `RES` | Residential proxy (PX10+) | `IsProxy` |
| `SES` | Search-engine spider | *(no flag)* |
| `-` | Not a proxy | *(no flag)* |

Because IP2Proxy assigns one type per address, the flags `IsVPN`, `IsProxy`,
`IsTor`, and `IsHosting` are mutually exclusive when set by this database
alone.

### 3. MaxMind GeoLite2-ASN lookup

The address is also looked up in the GeoLite2-ASN database, which maps IP
ranges to their Autonomous System Number (ASN) and organisation name. Two
things happen here:

**Hosting detection:** `IsHosting` is set to `true` if the IP's ASN appears
in the package's built-in curated list of known hosting and cloud provider
ASNs (DigitalOcean, AWS, GCP, Azure, Hetzner, Vultr, OVH, Cloudflare, and
many others). This catches hosting-range addresses that IP2Proxy does not
classify as `DCH` — the original motivation for adding this second source.
The final `IsHosting` flag is the **union** of both databases.

**Metadata:** The organisation name of the ASN (e.g. `"DIGITALOCEAN-ASN"`) is
exposed as `Result.AsnOrg`. This does not affect scoring but provides useful
context for logging and auditing in backend services.

### 4. Tor DNS check (IPv4 only)

After both database lookups, if the address has not already been identified as
a Tor exit node and the Tor DNS check is enabled (the default), the package
queries the Tor Project's authoritative DNSBL:

```text
<d>.<c>.<b>.<a>.dnsel.torproject.org
```

A response of `127.0.0.2` confirms the address is a known Tor exit node. The
lookup honours the `context.Context` passed to `Check`/`CheckString`, so
deadlines and cancellation work as expected.

The DNS check intentionally complements the database: the DNSBL is updated in
near-real-time and therefore catches newly activated exit nodes that have not
yet appeared in the monthly database snapshot. If the lookup fails for any
reason (timeout, SERVFAIL, no network) the error is silently discarded and the
database result stands — the check is best-effort.

The Tor DNSBL does not support IPv6. IPv6 Tor exit nodes are detected by the
databases only.

### 5. Threat scoring

The four boolean flags are combined into a numeric score, which is mapped to a
named threat level. See [Threat scoring](#threat-scoring) below.

---

## Data sources

### IP2Proxy LITE (primary — anonymisation detection)

**URL:** <https://lite.ip2location.com>
**License:** Creative Commons Attribution-ShareAlike 4.0
**Cost:** Free (registration required)
**Recommended tier:** PX2
**Approximate size:** ~6 MB
**Update cadence:** Monthly

IP2Proxy is the primary source for VPN, proxy, and Tor classification. The
free LITE PX2 tier provides proxy type, ISP, and country fields and is
sufficient for the core detection signals. Higher tiers (PX5+) additionally
populate the `FraudScore` field in `Result`. A paid `.BIN` file of any tier
can be dropped in without code changes.

### MaxMind GeoLite2-ASN (secondary — hosting detection + metadata)

**URL:** <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>
**License:** Creative Commons Attribution-ShareAlike 4.0
**Cost:** Free (registration required)
**Approximate size:** ~9 MB
**Update cadence:** Weekly

GeoLite2-ASN maps IP ranges to ASN numbers and organisation names. The package
uses it for two purposes: detecting hosting providers via a curated ASN list,
and populating the `AsnOrg` metadata field. The weekly update cadence makes it
one of the freshest free sources for ASN data.

The built-in ASN list covers the most widely encountered hosting and cloud
providers. It will not catch every provider, particularly smaller or newer
ones. Coverage is deliberately conservative to minimise false positives.

### Tor Project DNSBL (supplementary — Tor only)

**URL:** <https://www.torproject.org/>
**Cost:** Free
**Requires:** Outbound DNS resolution (IPv4 only)
**Update cadence:** Near-real-time

The Tor Project maintains an authoritative DNSBL of active exit nodes. It
provides the most up-to-date Tor classification available and complements the
monthly IP2Proxy snapshot. Enabled by default; disable with
`WithTorDNSCheck(false)` for fully offline operation.

---

## Getting started

### Prerequisites

1. **Go 1.21 or later.**

2. **IP2Proxy LITE PX2 database.** Download `IP2PROXY-LITE-PX2.BIN` (~6 MB)
   from <https://lite.ip2location.com>. Free registration required.

3. **MaxMind GeoLite2-ASN database.** Download `GeoLite2-ASN.mmdb` (~9 MB)
   from <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>.
   Free registration required.

4. **Keep both databases current.** IP2Proxy is updated monthly; GeoLite2-ASN
   is updated weekly. Schedule periodic downloads and restart the service to
   load the new files.

### Install

```sh
go get github.com/bobadilla-tech/go-ip-intelligence/ipi
```

### Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/bobadilla-tech/go-ip-intelligence/ipi"
)

func main() {
    client, err := ipi.New(
        ipi.WithDatabasePath("/etc/ip2proxy/IP2PROXY-LITE-PX2.BIN"),
        ipi.WithASNDatabasePath("/etc/maxmind/GeoLite2-ASN.mmdb"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    result, err := client.CheckString(context.Background(), "134.122.0.1")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("VPN:     %v\n", result.IsVPN)
    fmt.Printf("Proxy:   %v\n", result.IsProxy)
    fmt.Printf("Tor:     %v\n", result.IsTor)
    fmt.Printf("Hosting: %v\n", result.IsHosting)
    fmt.Printf("ASN Org: %s\n", result.AsnOrg)
    fmt.Printf("Threat:  %s\n", result.Threat)
}
```

#### Disabling the Tor DNS check

```go
client, err := ipi.New(
    ipi.WithDatabasePath("/etc/ip2proxy/IP2PROXY-LITE-PX2.BIN"),
    ipi.WithASNDatabasePath("/etc/maxmind/GeoLite2-ASN.mmdb"),
    ipi.WithTorDNSCheck(false),
)
```

#### Using a request-scoped context

```go
ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
defer cancel()

result, err := client.CheckString(ctx, ipStr)
```

The timeout applies to the Tor DNS lookup only. Both database lookups are
in-memory and are not affected by the context.

---

## API reference

### `New(opts ...Option) (*Client, error)`

Creates a new `Client`. Both `WithDatabasePath` and `WithASNDatabasePath` are
required. Returns an error if either is missing or if either file cannot be
opened. When IP2Proxy opens successfully but the ASN database fails, the
IP2Proxy handle is closed before returning.

### `(*Client) Close()`

Releases the file handles held by both databases. Call when the `Client` is no
longer needed (typically via `defer`).

### `(*Client) Check(ctx context.Context, ip net.IP) (*Result, error)`

Analyses a `net.IP` value. Returns an error only if the IP is nil, the
internal representation is invalid, or a database lookup fails.

Private and reserved addresses return immediately with all flags `false` and
`Threat` set to `ThreatNone`.

### `(*Client) CheckString(ctx context.Context, ipStr string) (*Result, error)`

Convenience wrapper around `Check` that accepts an IP address string. Returns
an error if the string is not a valid IPv4 or IPv6 address.

### `Result`

```go
type Result struct {
    IP         net.IP      // 16-byte canonical form
    IsVPN      bool        // IP2Proxy: proxy type VPN
    IsProxy    bool        // IP2Proxy: proxy type PUB, WEB, or RES
    IsTor      bool        // IP2Proxy and/or Tor DNSBL
    IsHosting  bool        // IP2Proxy DCH or ASN in curated hosting list
    Score      int         // raw weighted score (see Threat scoring)
    Threat     ThreatLevel // None / Low / Medium / High / Critical
    FraudScore int         // 0–100; 0 means unavailable (requires IP2Proxy PX5+)
    AsnOrg     string      // MaxMind: ASN organisation name; empty if unavailable
}
```

### `ThreatLevel`

```go
const (
    ThreatNone     ThreatLevel = 0
    ThreatLow      ThreatLevel = 1
    ThreatMedium   ThreatLevel = 2
    ThreatHigh     ThreatLevel = 3
    ThreatCritical ThreatLevel = 4
)
```

`ThreatLevel` implements `fmt.Stringer`: `result.Threat.String()` returns
`"None"`, `"Low"`, `"Medium"`, `"High"`, or `"Critical"`.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `WithDatabasePath(path string)` | *(required)* | Path to the IP2Proxy `.BIN` file |
| `WithASNDatabasePath(path string)` | *(required)* | Path to the GeoLite2-ASN `.mmdb` file |
| `WithTorDNSCheck(enabled bool)` | `true` | Enable/disable the Tor DNSBL lookup |

---

## Threat scoring

Each detected signal contributes a fixed number of points to the score. The
score is then mapped to a named level.

### Weights

| Signal | Points | Rationale |
| --- | --- | --- |
| Tor exit node | 3 | Strongest anonymisation intent; exit node operators explicitly route others' traffic |
| VPN | 2 | Strong anonymisation signal |
| Proxy | 2 | Strong anonymisation signal |
| Hosting / DCH | 1 | Context signal only; many legitimate services run on cloud infrastructure |

Hosting is intentionally weighted low. A large fraction of legitimate API
traffic originates from cloud providers (automated jobs, backend services, CI
pipelines). Flagging it alone would generate significant false positives. It
is included so that hosting combined with any other signal escalates the level
accordingly.

### Level mapping

| Score | Level | Typical causes |
| --- | --- | --- |
| 0 | `None` | Regular residential or business ISP |
| 1 | `Low` | Hosting / cloud IP only |
| 2–3 | `Medium` | VPN, proxy, or Tor (database only) |
| 4–5 | `High` | Two signals active (e.g. VPN + hosting) |
| ≥ 6 | `Critical` | Three or more signals |

---

## CLI tool

A command-line tool is included for testing and one-off lookups.

### Build

```sh
go build -o ipi ./cmd/ipi
```

### Run

```sh
ipi -db <proxy-db> -asn-db <asn-db> <ip> [<ip>...]
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-db` | *(required)* | Path to the IP2Proxy `.BIN` database file |
| `-asn-db` | *(required)* | Path to the GeoLite2-ASN `.mmdb` file |
| `-no-tor-dns` | `false` | Disable the Tor DNSBL lookup |

### Example output

```text
IP:      134.122.0.1
VPN:     false
Proxy:   false
Tor:     false
Hosting: true
Score:   1
Threat:  Low
ASN Org: DIGITALOCEAN-ASN
---
IP:      185.220.101.1
VPN:     false
Proxy:   false
Tor:     true
Hosting: false
Score:   3
Threat:  Medium
ASN Org: RETN-AS
---
IP:      192.168.1.1
VPN:     false
Proxy:   false
Tor:     false
Hosting: false
Score:   0
Threat:  None
---
```

---

## Tradeoffs

### Local databases vs. external API

This package performs all lookups locally with no calls to any external HTTP
API at query time.

**Advantages:**

- No per-request latency from an external service.
- No API rate limits, quotas, or costs per query.
- Works fully offline (except the Tor DNS check, which is opt-out).
- No dependency on a third party's uptime at request time.
- Data never leaves your infrastructure.

**Disadvantages:**

- Coverage is frozen at the last database download.
- Two database files must be managed and refreshed out-of-band.
- The free LITE tiers have lower coverage than paid commercial products.

External APIs (e.g. ipinfo.io, IPQualityScore) typically have more up-to-date
coverage and richer signals, but introduce network latency on every request and
may have rate-limit and cost implications. This package deliberately prioritises
offline reliability over coverage breadth.

### Two databases vs. one

Using two complementary databases (IP2Proxy + GeoLite2-ASN) produces better
hosting detection than either alone, at the cost of an additional ~9 MB of
memory and a second in-memory lookup per `Check` call. The benefit is
illustrated directly: IP2Proxy marks `134.122.0.1` (DigitalOcean) as "not a
proxy", while the ASN lookup identifies its ASN (14061) as a known hosting
provider and sets `IsHosting = true`.

### Curated ASN list maintenance

The hosting ASN list is hardcoded and covers the most widely encountered
providers. It will not detect every hosting provider, particularly:

- Smaller regional providers not in the list.
- New providers whose ASN was assigned after the last list update.
- Providers that have reassigned or renumbered their ASNs.

This is a deliberate tradeoff: a conservative list minimises false positives
(flagging legitimate ISP traffic as hosting). The GeoLite2-ASN database
itself is updated weekly, but the ASN list embedded in the package only
changes with a new package release.

### Free vs. paid IP2Proxy tiers

| Aspect | LITE PX2 (free) | Paid tiers |
| --- | --- | --- |
| VPN detection | Good | Excellent |
| Proxy detection | Good | Excellent |
| Tor detection | Good | Excellent |
| Residential proxies | Not included | PX10+ |
| Fraud score | Not included | PX5+ |
| Update cadence | Monthly | Monthly |

A paid `.BIN` file of any tier can be dropped in without code changes.
`FraudScore` populates automatically with PX5+.

---

## Performance

### Database I/O

Both databases are loaded into memory at startup. All subsequent lookups are
in-memory operations with no disk I/O. Typical combined lookup latency for
both databases is in the low-microsecond range.

### Concurrency

`Client` is safe for concurrent use by multiple goroutines. Both the IP2Proxy
and GeoLite2-ASN libraries are thread-safe.

### Tor DNS check latency

The Tor DNS check adds one DNS round-trip per `Check` call for non-Tor
addresses (1–5 ms on a typical cloud instance). If the address is already
identified as Tor by the database, the check is skipped.

Mitigations:

1. **Set a context deadline** — the DNS lookup respects the context:

   ```go
   ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
   defer cancel()
   ```

2. **Disable the check** with `WithTorDNSCheck(false)` for sub-millisecond
   requirements.

3. **Cache results externally** (see [Possible improvements](#possible-improvements)).

### Memory footprint

| Database | Approximate size |
| --- | --- |
| IP2Proxy LITE PX2 | ~6 MB |
| MaxMind GeoLite2-ASN | ~9 MB |
| **Total** | **~15 MB** |

---

## Known limitations

1. **IPv6 Tor detection is database-only.** The Tor Project's DNSBL does not
   support IPv6 queries. IPv6 Tor exit nodes are only detected if they appear
   in the IP2Proxy database.

2. **Database freshness.** VPN, proxy, and hosting detections are as current as
   the last database download. The Tor DNS check partially offsets this for
   Tor exit nodes.

3. **Single proxy type per address (IP2Proxy).** IP2Proxy assigns one primary
   type per address. A VPN server on cloud infrastructure is classified as
   `VPN`, not also `DCH`. The GeoLite2-ASN lookup mitigates this for
   `IsHosting` specifically.

4. **Curated ASN list coverage.** Only ASNs in the built-in list trigger
   `IsHosting` via the ASN path. Providers not on the list are only detected
   if IP2Proxy classifies them as `DCH`.

5. **No residential proxy detection at the LITE tier.** Requires IP2Proxy
   PX10 or higher.

6. **Database reload requires restart.** Both databases are opened once at
   `New` time. Loading updated files requires closing and re-creating the
   `Client`.

7. **DNS errors are silently swallowed.** Tor DNSBL failures fall back to the
   database result with no indication in `Result`. A sustained DNS outage
   silently degrades Tor detection to database-only coverage.

---

## Possible improvements

### Result caching (LRU)

At high request rates the same addresses recur frequently. Wrapping
`Check`/`CheckString` with an in-memory LRU cache keyed by IP string would
eliminate redundant database lookups and the Tor DNS round-trip for recently
seen addresses. Libraries such as
[`github.com/hashicorp/golang-lru/v2`](https://github.com/hashicorp/golang-lru)
integrate cleanly.

### Zero-downtime database reload

The `Client` could watch both database files for changes (using `fsnotify`)
and hot-swap the underlying database handles under a read-write mutex, removing
the need for a service restart on monthly database updates.

### IPv6 Tor detection via exit node list

The Tor Project publishes a full exit node list at
`https://check.torproject.org/torbulkexitlist`. Periodically downloading and
indexing this list in memory would add IPv6 Tor detection and allow fully
offline Tor classification with near-real-time freshness.
