package checker

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// CheckSSL connects to host:port via TLS and verifies the certificate
// is valid for host and not expired. Returns true on success.
func CheckSSL(host string, port int, log *slog.Logger) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp",
		addr,
		&tls.Config{ServerName: host},
	)
	if err != nil {
		log.Error("ssl check failed", "addr", addr, "err", err)
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Error("ssl check: no certificates", "addr", addr)
		return false
	}

	cert := certs[0]
	now := time.Now()
	if now.After(cert.NotAfter) {
		log.Error("ssl check: certificate expired", "addr", addr, "expired", cert.NotAfter)
		return false
	}

	log.Info("ssl check: OK", "addr", addr, "expires", cert.NotAfter.Format("2006-01-02"))
	return true
}
