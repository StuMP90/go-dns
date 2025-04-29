package main

import (
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: godns <domain|ip>\n")
		os.Exit(1)
	}
	target := os.Args[1]
	isIP := net.ParseIP(target) != nil

	fmt.Printf("DNS records for %s:\n\n", target)

	if isIP {
		// Only PTR for IP addresses
		records, err := lookupPTR(target)
		if err != nil {
			fmt.Printf("PTR: error: %v\n", err)
		} else if len(records) > 0 {
			fmt.Printf("PTR:\n")
			for _, rec := range records {
				fmt.Printf("  %s\n", rec)
			}
		}
		return
	}

	lookupFuncs := []struct {
		typeName string
		lookup  func(string) ([]string, error)
	}{
		{"A", lookupA},
		{"AAAA", lookupAAAA},
		{"CNAME", lookupCNAME},
		{"MX", lookupMX},
		{"NS", lookupNS},
		{"TXT", lookupTXT},
		{"SOA", lookupSOA},
		{"SRV", lookupSRV},
		{"CERT", lookupCERT},
		{"DNAME", lookupDNAME},
	}

	for _, lf := range lookupFuncs {
		records, err := lf.lookup(target)
		if err != nil {
			fmt.Printf("%s: error: %v\n", lf.typeName, err)
			continue
		}
		if len(records) > 0 {
			fmt.Printf("%s:\n", lf.typeName)
			for _, rec := range records {
				fmt.Printf("  %s\n", rec)
			}
		}
	}
}

func lookupA(domain string) ([]string, error) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, addr := range addrs {
		if net.ParseIP(addr).To4() != nil {
			result = append(result, addr)
		}
	}
	return result, nil
}

func lookupAAAA(domain string) ([]string, error) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, addr := range addrs {
		if net.ParseIP(addr).To16() != nil && net.ParseIP(addr).To4() == nil {
			result = append(result, addr)
		}
	}
	return result, nil
}

func lookupCNAME(domain string) ([]string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return nil, err
	}
	return []string{cname}, nil
}

func lookupMX(domain string) ([]string, error) {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, mx := range mxs {
		result = append(result, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
	}
	return result, nil
}

func lookupNS(domain string) ([]string, error) {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, ns := range nss {
		result = append(result, ns.Host)
	}
	return result, nil
}

func lookupTXT(domain string) ([]string, error) {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}
	return txts, nil
}

// Helper for miekg/dns lookups
func dnsQuery(domain, qtype string) ([]dns.RR, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[qtype])
	resp, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer for %s type %s", domain, qtype)
	}
	return resp.Answer, nil
}

func lookupSOA(domain string) ([]string, error) {
	rrs, err := dnsQuery(domain, "SOA")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			result = append(result, fmt.Sprintf("NS: %s, Mbox: %s, Serial: %d", soa.Ns, soa.Mbox, soa.Serial))
		}
	}
	return result, nil
}

func lookupPTR(domain string) ([]string, error) {
	// For PTR, domain should be an IP address
	addr := domain
	if net.ParseIP(addr) == nil {
		return nil, fmt.Errorf("PTR lookup requires an IP address")
	}
	ptr, err := net.LookupAddr(addr)
	if err != nil {
		return nil, err
	}
	return ptr, nil
}

func lookupSRV(domain string) ([]string, error) {
	rrs, err := dnsQuery(domain, "SRV")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, rr := range rrs {
		if srv, ok := rr.(*dns.SRV); ok {
			result = append(result, fmt.Sprintf("%s %d %d %d", srv.Target, srv.Port, srv.Priority, srv.Weight))
		}
	}
	return result, nil
}

func lookupCERT(domain string) ([]string, error) {
	rrs, err := dnsQuery(domain, "CERT")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, rr := range rrs {
		if cert, ok := rr.(*dns.CERT); ok {
			result = append(result, fmt.Sprintf("Type: %d, KeyTag: %d, Algorithm: %d, Certificate: %x", cert.Type, cert.KeyTag, cert.Algorithm, cert.Certificate))
		}
	}
	return result, nil
}

func lookupDNAME(domain string) ([]string, error) {
	rrs, err := dnsQuery(domain, "DNAME")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, rr := range rrs {
		if dname, ok := rr.(*dns.DNAME); ok {
			result = append(result, dname.Target)
		}
	}
	return result, nil
}
