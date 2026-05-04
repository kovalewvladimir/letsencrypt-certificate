package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"letsencrypt-certificate/internal/acme"
	"letsencrypt-certificate/internal/checker"
	"letsencrypt-certificate/internal/config"
	"letsencrypt-certificate/internal/deployer"
	"letsencrypt-certificate/internal/dns"
	"letsencrypt-certificate/internal/nic"
	"letsencrypt-certificate/internal/notifier"
)

type certResult struct {
	cert config.CertificateConfig
	res  *acme.Result
	err  error
}

func main() {
	configPath := flag.String("config", "config.ini", "path to config.ini")
	debug := flag.Bool("debug", false, "включить уровень логирования DEBUG")
	flag.Parse()

	logFileName := time.Now().Format("2006-01-02_15-04-05") + ".log"

	// --- Logger ---
	log := buildLogger("", logFileName, *debug, config.HTTPLogConfig{})

	// --- Config ---
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("не удалось загрузить конфигурацию", "err", err)
		os.Exit(1)
	}

	// Reinitialize logger with file output if configured.
	log = buildLogger(cfg.LogDir, logFileName, *debug, cfg.HTTPLog)
	log.Info("letsencrypt-certificate запущен", "config", *configPath)

	// --- Notifiers ---
	notifiers := notifier.NewFromConfig(cfg.Notifiers, log)

	hostname, _ := os.Hostname()
	notifier.SendAll(notifiers, fmt.Sprintf(
		"<b>Запускаю обновление сертификатов</b>\nХост: <code>%s</code>", hostname,
	), log)

	// --- NIC.RU client ---
	nicClient := nic.New(cfg.NIC.AppLogin, cfg.NIC.AppPassword, cfg.NICTokenFile, log)
	if err := nicClient.Authorize(cfg.NIC.Username, cfg.NIC.Password); err != nil {
		fatalf(notifiers, log, "ошибка авторизации NIC: %v", err)
	}

	var nicMu sync.Mutex
	updateTXT := func(domain, value string) error {
		nicMu.Lock()
		defer nicMu.Unlock()
		name := buildACMEName(domain, cfg.NIC.Domain)
		return nicClient.UpdateTXTRecord(cfg.NIC.Service, cfg.NIC.Domain, name, value)
	}

	waitTXT := func(domain, value string) error {
		nsIPs, err := dns.GetNameserverIPs(domain, cfg.DNS.Resolver, log)
		if err != nil {
			return err
		}
		interval := time.Duration(cfg.DNS.CheckIntervalSec) * time.Second
		return dns.WaitForTXT(domain, value, nsIPs, interval, cfg.DNS.CheckMaxAttempts, log)
	}

	// --- Obtain certificates (sequential start, parallel wait) ---
	results := make(chan certResult, len(cfg.Certificates))
	var wg sync.WaitGroup

	go func() {
		for _, cert := range cfg.Certificates {
			wg.Add(1)
			go func(cert config.CertificateConfig) {
				defer wg.Done()
				certLog := log.With("cert", cert.Name)
				certLog.Info("получение сертификата", "domains", cert.Domains)
				res, err := acme.ObtainCertificate(
					cfg.ACME.DirectoryURL,
					cfg.ACME.Email,
					cert.Domains,
					cfg.CertificateFolder,
					updateTXT,
					waitTXT,
					certLog,
				)
				results <- certResult{cert: cert, res: res, err: err}
			}(cert)
		}
		wg.Wait()
		close(results)
	}()

	// --- Collect results & deploy ---
	allOK := true
	for r := range results {
		if r.err != nil {
			log.Error("ошибка получения сертификата", "name", r.cert.Name, "err", r.err)
			notifier.SendAll(notifiers, fmt.Sprintf(
				"❌ <b>Ошибка сертификата %s</b>\n%v", r.cert.Name, r.err,
			), log)
			allOK = false
			continue
		}

		log.Info("сертификат получен", "name", r.cert.Name,
			"private", r.res.PrivatePath, "fullchain", r.res.FullchainPath)

		if err := deploy(r.cert, r.res, log); err != nil {
			log.Error("ошибка деплоя", "name", r.cert.Name, "err", err)
			notifier.SendAll(notifiers, fmt.Sprintf(
				"❌ <b>Ошибка деплоя %s</b>\n%v", r.cert.Name, err,
			), log)
			allOK = false
		}
	}

	// --- SSL verification ---
	var sb strings.Builder
	sb.WriteString("<b>Сертификаты:</b>\n")
	for _, cert := range cfg.Certificates {
		for _, host := range cert.Domains {
			for _, port := range cert.Ports {
				if checker.CheckSSL(host, port, log) {
					fmt.Fprintf(&sb, "    ✅ %s:%d\n", host, port)
				} else {
					fmt.Fprintf(&sb, "    ❌ %s:%d\n", host, port)
					allOK = false
				}
			}
		}
	}

	if !allOK {
		sb.WriteString("\n⚠️⚠️⚠️ <b>Проверьте логи на сервере</b> ⚠️⚠️⚠️")
	}
	notifier.SendAll(notifiers, sb.String(), log)
	log.Info("завершено", "success", allOK)
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

func buildLogger(logDir, logFileName string, debug bool, httpCfg config.HTTPLogConfig) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})

	var handlers []slog.Handler
	handlers = append(handlers, stderr)

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			slog.New(stderr).Warn("не удалось создать директорию для лога, пишу только в stderr", "dir", logDir, "err", err)
		} else {
			logFile := filepath.Join(logDir, logFileName)
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				slog.New(stderr).Warn("не удалось открыть файл лога", "file", logFile, "err", err)
			} else {
				handlers = append(handlers, slog.NewTextHandler(f, &slog.HandlerOptions{Level: level}))
			}
		}
	}

	if httpCfg.Enable {
		path := httpCfg.Path
		if path != "" && path[0] != '/' {
			path = "/" + path
		}
		rawURL := "http://" + httpCfg.Host + ":" + httpCfg.Port + path + "/" + logFileName
		handlers = append(handlers, newHTTPHandler(rawURL, level, httpCfg.TimeoutSec, debug))
	}

	return slog.New(newMultiHandler(handlers...))
}

func fatalf(notifiers []notifier.Notifier, log *slog.Logger, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Error(msg)
	notifier.SendAll(notifiers, "⚠️ <b>Критическая ошибка</b>\n"+msg, log)
	os.Exit(1)
}
