package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// GetNameserverIPs resolves authoritative NS servers for domain to IP addresses.
// If the domain has no NS records it strips one label and tries the parent.
func GetNameserverIPs(domain string, log *slog.Logger) ([]string, error) {
	for {
		nss, err := net.LookupNS(domain)
		if err != nil {
			// Strip one label and try parent.
			dot := strings.Index(domain, ".")
			if dot < 0 {
				return nil, fmt.Errorf("dns: no NS records found for domain chain")
			}
			domain = domain[dot+1:]
			continue
		}

		nsHosts := make([]string, len(nss))
		for i, ns := range nss {
			nsHosts[i] = ns.Host
		}
		log.Debug("dns: найдены NS-серверы", "domain", domain, "ns", nsHosts)

		var ips []string
		for _, ns := range nss {
			addrs, err := net.LookupHost(ns.Host)
			if err != nil {
				continue
			}
			ips = append(ips, addrs...)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("dns: could not resolve any NS IP for %s", domain)
		}
		log.Debug("dns: IP-адреса NS-серверов", "domain", domain, "ips", ips)
		return ips, nil
	}
}

// WaitForTXT polls all provided nameserver IPs until the TXT record for
// "_acme-challenge.<domain>" equals value on every server, or until the
// attempt limit is reached.
func WaitForTXT(domain, value string, nsIPs []string, interval time.Duration, maxAttempts int, log *slog.Logger) error {
	// Work on a copy so we can remove IPs as they become consistent.
	remaining := make([]string, len(nsIPs))
	copy(remaining, nsIPs)

	acmeDomain := "_acme-challenge." + domain

	for attempt := 1; attempt <= maxAttempts && len(remaining) > 0; attempt++ {
		log.Info("dns: ожидание распространения TXT-записи", "attempt", attempt, "max", maxAttempts, "remaining_ns", len(remaining))
		time.Sleep(interval)

		var stillWaiting []string
		for _, nsIP := range remaining {
			txt, err := queryTXT(acmeDomain, nsIP)
			if err != nil {
				stillWaiting = append(stillWaiting, nsIP)
				log.Debug("dns: TXT-запись ещё не видна", "ns", nsIP, "err", err)
				continue
			}
			if txt == value {
				log.Info("dns: TXT-запись подтверждена", "ns", nsIP)
			} else {
				stillWaiting = append(stillWaiting, nsIP)
				log.Debug("dns: TXT-запись не совпадает", "ns", nsIP, "got", txt)
			}
		}
		remaining = stillWaiting
	}

	if len(remaining) > 0 {
		return fmt.Errorf("dns: TXT record did not propagate to %d nameserver(s) after %d attempts", len(remaining), maxAttempts)
	}
	return nil
}

// queryTXT queries a specific nameserver IP for TXT records of name.
func queryTXT(name, nsIP string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "udp", nsIP+":53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("no TXT records")
	}
	return txts[0], nil
}
