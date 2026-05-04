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
	list := flag.Bool("list", false, "показать имена всех сконфигурированных сертификатов и выйти")
	certs := flag.String("certs", "", "запустить только указанные сертификаты (через запятую, например: example.com,test.org)")
	force := flag.Bool("force", false, "принудительно обновить сертификаты, игнорируя срок истечения")
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

	// --- -list flag ---
	if *list {
		for _, c := range cfg.Certificates {
			fmt.Println(c.Name)
		}
		os.Exit(0)
	}

	// --- -certs flag ---
	if *certs != "" {
		names := strings.Split(*certs, ",")
		byName := make(map[string]config.CertificateConfig, len(cfg.Certificates))
		for _, c := range cfg.Certificates {
			byName[c.Name] = c
		}
		var unknown []string
		for _, n := range names {
			if _, ok := byName[n]; !ok {
				unknown = append(unknown, n)
			}
		}
		if len(unknown) > 0 {
			log.Error("неизвестные сертификаты", "names", strings.Join(unknown, ", "))
			os.Exit(1)
		}
		filtered := make([]config.CertificateConfig, 0, len(names))
		for _, n := range names {
			filtered = append(filtered, byName[n])
		}
		cfg.Certificates = filtered
	}

	// --- Notifiers ---
	notifiers := notifier.NewFromConfig(cfg.Notifiers, log)

	hostname, _ := os.Hostname()
	notifier.SendAll(notifiers, fmt.Sprintf(
		"<b>Проверяю сертификаты</b>\nХост: <code>%s</code>", hostname,
	), log)

	// --- Определяем, какие сертификаты нужно обновить ---
	type skipInfo struct {
		cert     config.CertificateConfig
		daysLeft int
	}
	var toRenew []config.CertificateConfig
	var toSkip []skipInfo

	for _, cert := range cfg.Certificates {
		renew, days := needsRenewal(cert, *force, log)
		if renew {
			toRenew = append(toRenew, cert)
		} else {
			toSkip = append(toSkip, skipInfo{cert: cert, daysLeft: days})
		}
	}

	allOK := true
	var sb strings.Builder
	sb.WriteString("<b>Сертификаты:</b>\n")

	// Сертификаты, которые не требуют обновления
	for _, s := range toSkip {
		log.Info("сертификат актуален, пропускаю", "cert", s.cert.Name, "days_left", s.daysLeft)
		fmt.Fprintf(&sb, "  ✅ <b>%s</b> — %d дней до истечения\n", s.cert.Name, s.daysLeft)
	}

	if len(toRenew) == 0 {
		log.Info("все сертификаты актуальны, обновление не требуется")
		notifier.SendAll(notifiers, sb.String(), log)
		log.Info("завершено", "success", true)
		return
	}

	// --- NIC.RU client (инициализируем только если есть что обновлять) ---
	nicClient := nic.New(cfg.NIC.AppLogin, cfg.NIC.AppPassword, cfg.NIC.TokenFile, log)
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
	results := make(chan certResult, len(toRenew))
	var wg sync.WaitGroup

	go func() {
		for _, cert := range toRenew {
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
	for r := range results {
		if r.err != nil {
			log.Error("ошибка получения сертификата", "name", r.cert.Name, "err", r.err)
			allOK = false
			continue
		}

		log.Info("сертификат получен", "name", r.cert.Name,
			"private", r.res.PrivatePath, "fullchain", r.res.FullchainPath)

		if err := deploy(r.cert, r.res, log); err != nil {
			log.Error("ошибка деплоя", "name", r.cert.Name, "err", err)
			allOK = false
		}
	}

	// --- SSL verification для обновлённых сертификатов ---
	for _, cert := range toRenew {
		certOK := true
		for _, host := range cert.Domains {
			for _, port := range cert.Ports {
				if !checker.CheckSSL(host, port, log) {
					certOK = false
					allOK = false
				}
			}
		}
		if certOK {
			fmt.Fprintf(&sb, "  🔄 <b>%s</b> — обновлён ✅\n", cert.Name)
		} else {
			fmt.Fprintf(&sb, "  🔄 <b>%s</b> — обновлён ❌\n", cert.Name)
		}
	}

	if !allOK {
		sb.WriteString("\n⚠️⚠️⚠️ <b>Проверьте логи на сервере</b> ⚠️⚠️⚠️")
		if cfg.LogDir != "" {
			fmt.Fprintf(&sb, "\n<code>%s</code>", filepath.Join(cfg.LogDir, logFileName))
		}
		if cfg.HTTPLog.Enable && cfg.HTTPLog.ReadPort != "" {
			path := cfg.HTTPLog.Path
			if path != "" && path[0] != '/' {
				path = "/" + path
			}
			fmt.Fprintf(&sb, "\nhttp://%s:%s%s/%s", cfg.HTTPLog.Host, cfg.HTTPLog.ReadPort, path, logFileName)
		}
	}
	notifier.SendAll(notifiers, sb.String(), log)
	log.Info("завершено", "success", allOK)
}

// needsRenewal returns true if the certificate needs to be renewed.
// Also returns the number of days left until expiry (or -1 on error).
func needsRenewal(cert config.CertificateConfig, force bool, log *slog.Logger) (bool, int) {
	if force {
		log.Info("принудительное обновление", "cert", cert.Name)
		return true, -1
	}
	if len(cert.Domains) == 0 || len(cert.Ports) == 0 {
		return true, -1
	}
	days, err := checker.DaysUntilExpiry(cert.Domains[0], cert.Ports[0], log.With("cert", cert.Name))
	if err != nil {
		log.Info("не удалось проверить срок — планирую обновление", "cert", cert.Name)
		return true, -1
	}
	if days <= cert.RenewBeforeDays {
		log.Info("сертификат скоро истечёт — планирую обновление", "cert", cert.Name,
			"days_left", days, "threshold", cert.RenewBeforeDays)
		return true, days
	}
	return false, days
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
