package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/kovalewvladimir/letsencrypt-certificate/internal/acme"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/checker"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/config"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/deployer"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/dns"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/nic"
	"github.com/kovalewvladimir/letsencrypt-certificate/internal/notifier"
)

const certStartDelay = 600 * time.Second

type certResult struct {
	cert config.CertificateConfig
	res  *acme.Result
	err  error
}

func main() {
	configPath := flag.String("config", "config.ini", "path to config.ini")
	flag.Parse()

	// --- Logger ---
	log := buildLogger("")

	// --- Config ---
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Reinitialize logger with file output if configured.
	log = buildLogger(cfg.LogFile)
	log.Info("letsencrypt-certificate started", "config", *configPath)

	// --- Notifiers ---
	notifiers := notifier.NewFromConfig(cfg.Notifiers, log)

	hostname, _ := os.Hostname()
	notifier.SendAll(notifiers, fmt.Sprintf(
		"<b>Запускаю обновление сертификатов</b>\nХост: <code>%s</code>", hostname,
	), log)

	// --- NIC.RU client ---
	nicClient := nic.New(cfg.NIC.AppLogin, cfg.NIC.AppPassword, cfg.NICTokenFile, log)
	if err := nicClient.Authorize(cfg.NIC.Username, cfg.NIC.Password); err != nil {
		fatalf(notifiers, log, "NIC authorization failed: %v", err)
	}

	updateTXT := func(domain, value string) error {
		name := buildACMEName(domain, cfg.NIC.Domain)
		return nicClient.UpdateTXTRecord(cfg.NIC.Service, cfg.NIC.Domain, name, value)
	}

	waitTXT := func(domain, value string) error {
		nsIPs, err := dns.GetNameserverIPs(domain)
		if err != nil {
			return err
		}
		interval := time.Duration(cfg.DNS.CheckIntervalSec) * time.Second
		return dns.WaitForTXT(domain, value, nsIPs, interval, cfg.DNS.CheckMaxAttempts, log)
	}

	// --- Obtain certificates (sequential start, parallel wait) ---
	results := make(chan certResult, len(cfg.Certificates))
	var wg sync.WaitGroup

	for i, cert := range cfg.Certificates {
		if i > 0 {
			log.Info("waiting before starting next certificate", "delay", certStartDelay)
			time.Sleep(certStartDelay)
		}

		wg.Add(1)
		go func(cert config.CertificateConfig) {
			defer wg.Done()
			log.Info("obtaining certificate", "name", cert.Name, "domains", cert.Domains)
			res, err := acme.ObtainCertificate(
				cfg.ACME.DirectoryURL,
				cfg.ACME.Email,
				cert.Domains,
				cfg.CertificateFolder,
				updateTXT,
				waitTXT,
				log,
			)
			results <- certResult{cert: cert, res: res, err: err}
		}(cert)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// --- Collect results & deploy ---
	allOK := true
	for r := range results {
		if r.err != nil {
			log.Error("certificate failed", "name", r.cert.Name, "err", r.err)
			notifier.SendAll(notifiers, fmt.Sprintf(
				"❌ <b>Ошибка сертификата %s</b>\n%v", r.cert.Name, r.err,
			), log)
			allOK = false
			continue
		}

		log.Info("certificate obtained", "name", r.cert.Name,
			"private", r.res.PrivatePath, "fullchain", r.res.FullchainPath)

		if err := deploy(r.cert, r.res, log); err != nil {
			log.Error("deploy failed", "name", r.cert.Name, "err", err)
			notifier.SendAll(notifiers, fmt.Sprintf(
				"❌ <b>Ошибка деплоя %s</b>\n%v", r.cert.Name, err,
			), log)
			allOK = false
		}
	}

	// --- SSL verification ---
	msg := "<b>Сертификаты:</b>\n"
	for _, cert := range cfg.Certificates {
		for _, host := range cert.Domains {
			for _, port := range cert.Ports {
				if checker.CheckSSL(host, port, log) {
					msg += fmt.Sprintf("    ✅ %s:%d\n", host, port)
				} else {
					msg += fmt.Sprintf("    ❌ %s:%d\n", host, port)
					allOK = false
				}
			}
		}
	}

	if !allOK {
		msg += "\n⚠️⚠️⚠️ <b>Проверьте логи на сервере</b> ⚠️⚠️⚠️"
	}
	notifier.SendAll(notifiers, msg, log)
	log.Info("done", "success", allOK)
}

func deploy(cert config.CertificateConfig, res *acme.Result, log *slog.Logger) error {
	d := cert.Deploy
	switch d.Type {
	case "local":
		return deployer.DeployLocal(
			res.PrivatePath, res.FullchainPath,
			d.PrivatePath, d.FullchainPath,
			d.Commands, log,
		)
	case "ssh":
		return deployer.DeploySSH(
			res.PrivatePath, res.FullchainPath,
			d.SSHHost, d.SSHUsername, d.SSHKeyPath,
			d.SSHPrivatePath, d.SSHFullchainPath,
			d.Commands, log,
		)
	default:
		return fmt.Errorf("unknown deploy type %q", d.Type)
	}
}

// buildACMEName returns the DNS TXT record name for an ACME challenge.
// If domain == rootDomain → "_acme-challenge"
// If domain == sub.rootDomain → "_acme-challenge.sub"
func buildACMEName(domain, rootDomain string) string {
	if domain == rootDomain {
		return "_acme-challenge"
	}
	sub := domain[:len(domain)-len(rootDomain)-1] // strip ".rootDomain"
	return "_acme-challenge." + sub
}

func buildLogger(logFile string) *slog.Logger {
	var writers []slog.Handler
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	_ = writers
	if logFile == "" {
		return slog.New(stderr)
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return slog.New(stderr)
	}
	// Write to both stderr and file using a multi-writer via tee.
	return slog.New(newMultiHandler(stderr,
		slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

func fatalf(notifiers []notifier.Notifier, log *slog.Logger, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Error(msg)
	notifier.SendAll(notifiers, "⚠️ <b>Критическая ошибка</b>\n"+msg, log)
	os.Exit(1)
}
