# go-ip-intelligence

A Go package for IP address intelligence. Given any IPv4 or IPv6 address it
determines whether the address belongs to a VPN provider, a proxy (public or
web), a Tor exit node, or a hosting/data-centre range, and derives a
structured threat level from those signals.

Designed for embedding in backend services: the `Client` is safe for
concurrent use, all detection runs locally against a bundled binary database,
and the public API is intentionally small.

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
|---|---|
| VPN | IP2Proxy database (proxy type `VPN`) |
| Public / web proxy | IP2Proxy database (proxy types `PUB`, `WEB`, `RES`) |
| Tor exit node | IP2Proxy database **+** Tor Project DNSBL |
| Hosting / data centre | IP2Proxy database (proxy type `DCH`) |
| Private / reserved IPs | Built-in RFC range check (no database I/O) |
| Threat level | Weighted score → `None / Low / Medium / High / Critical` |

---

## How it works

### 1. Private IP short-circuit

Before any external lookup the package checks whether the address falls inside
a private or reserved range (RFC 1918, loopback, link-local, CGNAT, test nets,
etc.). If it does, the function returns immediately with `ThreatNone` and all
flags `false`. This avoids unnecessary I/O for addresses that will never appear
in the database, and is the common case in internal services that also receive
traffic from load-balancers or health checks.

### 2. IP2Proxy database lookup

The address is looked up in the binary IP2Proxy database. The database assigns
each address a single primary **proxy type**:

| Type | Meaning | Flag set |
|---|---|---|
| `VPN` | VPN anonymizer | `IsVPN` |
| `TOR` | Tor exit node | `IsTor` |
| `DCH` | Data centre / hosting range | `IsHosting` |
| `PUB` | Public proxy | `IsProxy` |
| `WEB` | Web proxy | `IsProxy` |
| `RES` | Residential proxy (PX10+) | `IsProxy` |
| `SES` | Search-engine spider | *(no flag)* |
| `-`  | Not a proxy | *(no flag)* |

Because the database assigns one type per address, the four boolean flags
(`IsVPN`, `IsProxy`, `IsTor`, `IsHosting`) are mutually exclusive when set by
the database alone. They can accumulate only when the Tor DNS check (step 3)
promotes `IsTor` on an address the database already classified as something
else (rare in practice).

### 3. Tor DNS check (IPv4 only)

After the database step, if the address has not already been identified as a
Tor exit node and the Tor DNS check is enabled (the default), the package
queries the Tor Project's authoritative DNSBL:

```
<d>.<c>.<b>.<a>.dnsel.torproject.org
```

A response of `127.0.0.2` means the address is a known Tor exit node. This
lookup is performed using the system resolver and honours the `context.Context`
passed to `Check`/`CheckString`, so deadlines and cancellation work as
expected.

The DNS check intentionally complements rather than replaces the database: the
DNSBL is updated in near-real-time by the Tor Project and therefore catches
newly activated exit nodes that have not yet appeared in the monthly database
snapshot. If the DNS lookup fails for any reason (timeout, SERVFAIL, no
network) the error is silently discarded and the database result stands — the
check is best-effort.

The Tor DNSBL does not support IPv6. IPv6 Tor exit nodes are detected by the
database only.

### 4. Threat scoring

The four boolean flags are combined into a numeric score, which is then mapped
to a named threat level. See [Threat scoring](#threat-scoring) below.

---

## Data sources

### IP2Proxy LITE (primary)

**URL:** https://lite.ip2location.com
**License:** Creative Commons Attribution-ShareAlike 4.0
**Cost:** Free (registration required)
**Format:** Binary `.BIN` file
**Update cadence:** Monthly

IP2Proxy is a commercial database with a free LITE tier. The LITE tier covers
VPN, Tor, data-centre, and common proxy ranges with good accuracy. The
recommended tier for this package is **PX2**, which provides proxy type, ISP,
and country fields. Higher tiers (PX5+) additionally populate the
`FraudScore` field.

Coverage is not exhaustive. New VPN providers, fresh cloud infrastructure, and
residential proxies via lesser-known ISPs may not appear in the LITE database.
The paid commercial tiers have broader coverage; if your threat model requires
it, swapping in a higher-tier `.BIN` file requires no code changes.

### Tor Project DNSBL (secondary, Tor only)

**URL:** https://www.torproject.org/
**Cost:** Free
**Requires:** Outbound DNS resolution
**Update cadence:** Near-real-time

The Tor Project maintains an authoritative list of active exit nodes queried
via DNS. It is the most up-to-date source for Tor exit node classification.
This check is enabled by default and can be disabled with
`WithTorDNSCheck(false)` when the service must run without any outbound
network access.

---

## Getting started

### Prerequisites

1. **Go 1.21 or later.**

2. **An IP2Proxy `.BIN` database file.** Download the free LITE PX2 database
   from https://lite.ip2location.com. Registration is required. The file is
   named `IP2PROXY-LITE-PX2.BIN` and is approximately 6 MB.

3. **Keep the database current.** The LITE database is updated on the first
   day of each month. Set up a cron job or a CI pipeline step to download the
   latest file and replace the old one. The `Client` reads the file at
   startup, so a service restart (or a re-`New` call) is required to pick up
   an updated file.

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
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    result, err := client.CheckString(context.Background(), "1.2.3.4")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("VPN:     %v\n", result.IsVPN)
    fmt.Printf("Proxy:   %v\n", result.IsProxy)
    fmt.Printf("Tor:     %v\n", result.IsTor)
    fmt.Printf("Hosting: %v\n", result.IsHosting)
    fmt.Printf("Threat:  %s\n", result.Threat) // e.g. "Medium"
}
```

#### Disabling the Tor DNS check

```go
client, err := ipi.New(
    ipi.WithDatabasePath("/etc/ip2proxy/IP2PROXY-LITE-PX2.BIN"),
    ipi.WithTorDNSCheck(false), // rely on database only
)
```

#### Using a request-scoped context

```go
ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
defer cancel()

result, err := client.CheckString(ctx, ipStr)
```

The timeout applies to the Tor DNS lookup. The database lookup is synchronous
file I/O and is not affected by the context.

---

## API reference

### `New(opts ...Option) (*Client, error)`

Creates a new `Client`. Fails if `WithDatabasePath` is not provided or if the
database file cannot be opened.

### `(*Client) Close()`

Releases the file handle held by the database. Call this when the `Client` is
no longer needed (typically via `defer`).

### `(*Client) Check(ctx context.Context, ip net.IP) (*Result, error)`

Analyses a `net.IP` value. Returns an error only if the IP is nil, the
internal representation is invalid, or the database lookup fails.

Private and reserved addresses return immediately with all flags `false` and
`Threat` set to `ThreatNone`.

### `(*Client) CheckString(ctx context.Context, ipStr string) (*Result, error)`

Convenience wrapper around `Check` that accepts an IP address string. Returns
an error if the string is not a valid IPv4 or IPv6 address.

### `Result`

```go
type Result struct {
    IP         net.IP      // 16-byte form
    IsVPN      bool
    IsProxy    bool
    IsTor      bool
    IsHosting  bool
    Score      int         // raw weighted score
    Threat     ThreatLevel // None / Low / Medium / High / Critical
    FraudScore int         // 0–100; 0 means unavailable (requires PX5+)
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
|---|---|---|
| `WithDatabasePath(path string)` | *(required)* | Path to the IP2Proxy `.BIN` file |
| `WithTorDNSCheck(enabled bool)` | `true` | Enable/disable the Tor DNSBL lookup |

---

## Threat scoring

Each detected signal contributes a fixed number of points to the score. The
score is then mapped to a named level.

### Weights

| Signal | Points | Rationale |
|---|---|---|
| Tor exit node | 3 | Strongest anonymisation intent; exit node operators are explicitly routing others' traffic |
| VPN | 2 | Strong anonymisation signal; commonly used to mask origin |
| Proxy | 2 | Strong anonymisation signal |
| Hosting / DCH | 1 | Context signal only; many legitimate services run on cloud infrastructure |

Hosting is intentionally weighted low because a large fraction of legitimate
API traffic originates from cloud providers (automated jobs, backend services,
CI pipelines). Flagging it alone as a meaningful threat would generate
significant false positives. It is included in the score so that hosting
combined with any other signal escalates the level accordingly.

### Level mapping

| Score | Level | Typical causes |
|---|---|---|
| 0 | `None` | Regular residential or business ISP |
| 1 | `Low` | Hosting / cloud IP only |
| 2–3 | `Medium` | VPN, proxy, or Tor (database only) |
| 4–5 | `High` | Two signals active (e.g. VPN + hosting, or Tor confirmed by DNS) |
| ≥ 6 | `Critical` | Three or more signals (e.g. Tor + VPN + hosting) |

The maximum theoretical score is 8 (Tor + VPN + Proxy + Hosting), which
requires all four flags to be set simultaneously. In practice, because
IP2Proxy assigns a single primary proxy type per address, the database alone
cannot set more than one flag per address. A score above 3 therefore implies
that the Tor DNS check elevated `IsTor` on top of a database-identified VPN or
proxy address — a meaningful anomaly.

---

## CLI tool

A command-line tool is included for testing and one-off lookups.

### Build

```sh
go build -o ipi ./cmd/ipi
```

### Usage

```sh
ipi -db IP2PROXY-LITE-PX2.BIN <ip> [<ip>...]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-db` | *(required)* | Path to the IP2Proxy `.BIN` database file |
| `-no-tor-dns` | `false` | Disable the Tor DNSBL lookup |

### Example output

```
IP:      185.220.101.1
VPN:     false
Proxy:   false
Tor:     true
Hosting: false
Score:   3
Threat:  Medium
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

### Local database vs. external API

This package performs all lookups locally, with no calls to any external HTTP
API at query time. The tradeoff is:

**Advantages of local database:**
- No per-request latency from an external service.
- No API rate limits, quotas, or costs per query.
- Works fully offline (except the Tor DNS check, which is opt-out).
- No dependency on a third party's uptime at request time.
- Data never leaves your infrastructure.

**Disadvantages of local database:**
- Coverage is frozen at the last database download. Newly activated VPN
  servers or proxy nodes will not be detected until the next monthly refresh.
- The database file must be managed and kept current out-of-band.
- The free LITE tier has lower coverage than paid commercial products (see
  [Known limitations](#known-limitations)).

External APIs (e.g. ipinfo.io, IPQualityScore) typically have more up-to-date
coverage and richer signals, but introduce network latency on every request,
require outbound internet access, and may have cost and rate-limit
implications. This package deliberately prioritises offline reliability over
coverage breadth.

### Free LITE tier vs. paid database

IP2Proxy offers tiers from PX1 (proxy type only) up to PX10 (all fields
including residential proxy and fraud score). The free LITE PX2 tier covers
the core signals needed by this package. The practical tradeoffs are:

| Aspect | LITE PX2 (free) | Paid tiers |
|---|---|---|
| VPN detection | Good | Excellent |
| Proxy detection | Good | Excellent |
| Tor detection | Good | Excellent |
| Hosting/DCH | Good | Excellent |
| Residential proxies | Not included (PX10 only) | PX10+ |
| Fraud score | Not included (PX5+) | PX5+ |
| Update cadence | Monthly | Monthly (same) |
| License | CC BY-SA 4.0 | Commercial |

A paid `.BIN` file of any tier can be dropped in place of the free one with
no code changes. The `FraudScore` field in `Result` will populate automatically
if a PX5+ database is used.

### Single proxy type per address

IP2Proxy assigns each address a single primary proxy type. An address cannot
simultaneously be classified as `VPN` and `DCH` by the database alone. This
means:

- `IsVPN` and `IsHosting` will generally not both be `true` at once from the
  database perspective (a hosting-range VPN server would be classified as
  `VPN`, not `DCH`).
- Scores above 3 are only achievable when the Tor DNS check adds `IsTor` on
  top of a database-classified address.

This is a property of the upstream data source and is not something the package
can work around without introducing a second database or data source.

---

## Performance

### Database I/O

The IP2Proxy library reads the `.BIN` file into memory at `Open` time. All
subsequent lookups are in-memory binary searches with no file I/O. Typical
lookup latency is in the low microsecond range on modern hardware.

### Concurrency

`Client` is safe for concurrent use by multiple goroutines. The underlying
IP2Proxy library is thread-safe. No additional locking is performed by this
package.

### Tor DNS check latency

The Tor DNS check adds one DNS round-trip to each `Check` call for non-Tor
addresses. On a typical cloud instance with a nearby resolver this is 1–5 ms.
If the address is already identified as Tor by the database, the DNS check is
skipped entirely.

This latency can be significant at high throughput. Mitigations:

1. **Attach a tight deadline to the context.** The DNS lookup respects the
   context, so a 50–100 ms timeout caps the worst case:

   ```go
   ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
   defer cancel()
   result, _ := client.CheckString(ctx, ip)
   ```

2. **Disable the DNS check** with `WithTorDNSCheck(false)` if sub-millisecond
   lookups are required and the database coverage for Tor is sufficient for
   your use case.

3. **Add an external result cache** (see [Possible improvements](#possible-improvements)).

### Memory footprint

The IP2Proxy LITE PX2 database is approximately 6 MB on disk. It is loaded
entirely into memory, so plan for roughly that amount of additional heap
allocation per `Client` instance. In practice a single `Client` is shared
across the entire service lifetime.

---

## Known limitations

1. **IPv6 Tor detection is database-only.** The Tor Project's DNSBL
   (`dnsel.torproject.org`) does not support IPv6 queries. IPv6 Tor exit nodes
   are detected only if they appear in the IP2Proxy database, which may lag
   by up to one month.

2. **Database freshness.** All VPN, proxy, and hosting detections are as
   current as the last database download. A VPN provider that spun up new
   infrastructure after the last monthly snapshot will not be detected until
   the database is refreshed. The Tor DNS check partially offsets this for Tor
   exit nodes only.

3. **Single proxy type per address.** The database assigns one primary type
   per address. A VPN provider operating on cloud infrastructure will typically
   be classified as `VPN` and not also as `IsHosting`. The flags are therefore
   not fully independent signals.

4. **No residential proxy detection at the LITE tier.** Residential proxies
   (type `RES`) require IP2Proxy tier PX10 or higher. They are not included
   in the free LITE database.

5. **Database reload requires restart.** The database is opened once at `New`
   time. To pick up an updated database file the `Client` must be closed and
   re-created, which in practice means a service restart or a rolling
   redeployment.

6. **DNS errors are silently swallowed.** If the Tor DNSBL lookup fails, the
   result falls back to the database classification with no indication of the
   failure in the returned `Result`. This is intentional — the check is
   best-effort — but means a sustained DNS outage would silently degrade Tor
   detection to database-only coverage.

---

## Possible improvements

The following improvements are intentionally out of scope for the initial
implementation but are worth considering as the service scales.

### Result caching (LRU)

At high request rates the same IP addresses tend to recur frequently (scrapers,
bots, legitimate repeat users). Wrapping `Check`/`CheckString` with an in-memory
LRU cache keyed by the IP string would eliminate redundant database lookups and,
more importantly, the Tor DNS round-trip for previously seen addresses.

A typical implementation would use a fixed-capacity cache (e.g. 10 000 entries)
with a TTL of a few minutes. Libraries such as
[`github.com/hashicorp/golang-lru/v2`](https://github.com/hashicorp/golang-lru)
integrate cleanly.

### Zero-downtime database reload

Rather than requiring a process restart to pick up a new database, the `Client`
could watch the database file for changes (using `fsnotify`) and hot-swap the
underlying `ip2proxy.DB` pointer under a read-write mutex. This is especially
useful on long-running services where monthly restarts are disruptive.

### Additional data sources

A richer signal set could be built by layering additional databases alongside
IP2Proxy:

- **MaxMind GeoLite2-ASN** (free) — provides ASN and organisation names,
  useful for identifying well-known hosting providers not yet in IP2Proxy.
- **Firehol blocklists** — curated community blocklists of known malicious
  ranges that go beyond anonymisation proxies.
- **Custom CIDR allowlists / blocklists** — organisation-specific overrides
  for known-good or known-bad ranges that no public database covers.

### IPv6 Tor detection via downloaded exit list

The Tor Project publishes a full exit node list at
`https://check.torproject.org/torbulkexitlist` (and an extended version with
metadata at `https://onionoo.torproject.org`). Periodically downloading this
list and indexing it locally would provide IPv6 Tor exit node detection without
relying on the DNS check, and would allow fully offline Tor detection.

### Structured logging

The package currently discards DNS errors silently. For observability in a
production service, an optional logger interface (e.g.
`WithLogger(slog.Logger)`) would allow the caller to record detection
fallbacks, slow DNS lookups, and database version information.

### Metrics

Exposing Prometheus counters for `Check` calls broken down by threat level, DNS
check hits/misses, and detection source (database vs. DNS) would make it
straightforward to monitor the operational impact of the package in production.
