package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/bobadilla-tech/go-ip-intelligence/v2/ipi"
)

func main() {
	dbPath := flag.String("db", "", "path to IP2Proxy .BIN database file (required)")
	asnDBPath := flag.String("asn-db", "", "path to MaxMind GeoLite2-ASN .mmdb file (required)")
	cityDBPath := flag.String("city-db", "", "path to MaxMind GeoLite2-City .mmdb file (required)")
	noTorDNS := flag.Bool("no-tor-dns", false, "disable real-time Tor exit-node DNS check")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ipi -db <proxy-db> -asn-db <asn-db> -city-db <city-db> <ip> [<ip>...]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: -db flag is required")
		flag.Usage()
		os.Exit(1)
	}
	if *asnDBPath == "" {
		fmt.Fprintln(os.Stderr, "error: -asn-db flag is required")
		flag.Usage()
		os.Exit(1)
	}
	if *cityDBPath == "" {
		fmt.Fprintln(os.Stderr, "error: -city-db flag is required")
		flag.Usage()
		os.Exit(1)
	}
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one IP address argument is required")
		flag.Usage()
		os.Exit(1)
	}

	client, err := ipi.New(
		ipi.WithDatabasePath(*dbPath),
		ipi.WithASNDatabasePath(*asnDBPath),
		ipi.WithCityDatabasePath(*cityDBPath),
		ipi.WithTorDNSCheck(!*noTorDNS),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx := context.Background()
	exitCode := 0
	for _, ipStr := range flag.Args() {
		result, err := client.CheckString(ctx, ipStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			exitCode = 1
			continue
		}
		printResult(result)
	}
	os.Exit(exitCode)
}

func printResult(r *ipi.Result) {
	fmt.Printf("IP:      %s\n", net.IP(r.IP))
	fmt.Printf("VPN:     %v\n", r.IsVPN)
	fmt.Printf("Proxy:   %v\n", r.IsProxy)
	fmt.Printf("Tor:     %v\n", r.IsTor)
	fmt.Printf("Hosting: %v\n", r.IsHosting)
	fmt.Printf("Score:   %d\n", r.Score)
	fmt.Printf("Threat:  %s\n", r.Threat)
	if r.AsnNumber != 0 {
		fmt.Printf("ASN:     AS%d\n", r.AsnNumber)
	}
	if r.AsnOrg != "" {
		fmt.Printf("ASN Org: %s\n", r.AsnOrg)
	}
	if r.AsnRoute != "" {
		fmt.Printf("Route:   %s\n", r.AsnRoute)
	}
	if r.Country != "" {
		fmt.Printf("Country: %s (%s)\n", r.Country, r.CountryCode)
	}
	if r.City != "" {
		fmt.Printf("City:    %s\n", r.City)
	}
	if r.FraudScore > 0 {
		fmt.Printf("Fraud:   %d/100\n", r.FraudScore)
	}
	fmt.Println("---")
}
