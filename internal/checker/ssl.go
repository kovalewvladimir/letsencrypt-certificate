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
		log.Error("ssl: проверка не прошла", "addr", addr, "err", err)
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Error("ssl: нет сертификатов", "addr", addr)
		return false
	}

	cert := certs[0]

	// Сравниваем даты в локальном timezone сервера (настраивается через TZ).
	// cert.NotBefore приходит в UTC — конвертируем обе стороны в Local,
	// иначе сертификат выданный в 23:30 UTC (= 02:30 MSK) будет "вчерашним" по UTC.
	nowLocal := time.Now().In(time.Local)
	notBeforeLocal := cert.NotBefore.In(time.Local)

	nowY, nowM, nowD := nowLocal.Date()
	certY, certM, certD := notBeforeLocal.Date()

	if certY != nowY || certM != nowM || certD != nowD {
		log.Error("ssl: сертификат не обновлён сегодня",
			"addr", addr,
			"notBefore", notBeforeLocal.Format("2006-01-02 15:04 MST"),
			"today", nowLocal.Format("2006-01-02 MST"),
		)
		return false
	}

	log.Info("ssl: сертификат обновлён сегодня",
		"addr", addr,
		"notBefore", notBeforeLocal.Format("2006-01-02 15:04 MST"),
	)
	return true
}
