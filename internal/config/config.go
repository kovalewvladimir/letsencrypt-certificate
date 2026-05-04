package config

import (
	"fmt"
	"strconv"
	"strings"
)

type HTTPLogConfig struct {
	Enable     bool
	Host       string
	Port       string
	Path       string
	TimeoutSec int
}

type Config struct {
	LogDir            string
	CertificateFolder string
	NICTokenFile      string

	Telegram TelegramConfig
	ACME     ACMEConfig
	NIC      NICConfig
	DNS      DNSConfig
	HTTPLog  HTTPLogConfig

	Certificates []CertificateConfig

	// Notifiers holds raw notifier configs keyed by type (e.g. "telegram").
	Notifiers map[string]map[string]string
}

type TelegramConfig struct {
	Token     string
	Recipient string
}

type ACMEConfig struct {
	DirectoryURL string
	Email        string
}

type NICConfig struct {
	AppLogin    string
	AppPassword string
	Username    string
	Password    string
	Service     string
	Domain      string
}

type DNSConfig struct {
	CheckIntervalSec int
	CheckMaxAttempts int
	Resolver         string
}

type CertificateConfig struct {
	Name   string
	Domains []string
	Ports  []int
	Deploy DeployConfig
}

type DeployConfig struct {
	Type string // "local" or "ssh"

	// local
	PrivatePath   string
	FullchainPath string
	Commands      []string

	// ssh
	SSHHost          string
	SSHUsername      string
	SSHKeyPath       string
	SSHPrivatePath   string
	SSHFullchainPath string
}

func Load(path string) (*Config, error) {
	data, err := parseINI(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Notifiers: make(map[string]map[string]string),
	}

	// [log]
	cfg.LogDir = data.get("log", "folder")
	cfg.CertificateFolder = data.get("log", "certificate_folder")
	cfg.NICTokenFile = data.get("log", "nic_token_file")

	// [log.http]
	cfg.HTTPLog.TimeoutSec = 10
	cfg.HTTPLog.Enable = data.get("log.http", "enable") == "true"
	cfg.HTTPLog.Host = data.get("log.http", "host")
	cfg.HTTPLog.Port = data.get("log.http", "port")
	cfg.HTTPLog.Path = data.get("log.http", "path")
	if v := data.get("log.http", "timeout_sec"); v != "" {
		cfg.HTTPLog.TimeoutSec, _ = strconv.Atoi(v)
	}

	// [acme]
	cfg.ACME = ACMEConfig{
		DirectoryURL: data.get("acme", "directory_url"),
		Email:        data.get("acme", "email"),
	}

	// [nic]
	cfg.NIC = NICConfig{
		AppLogin:    data.get("nic", "app_login"),
		AppPassword: data.get("nic", "app_password"),
		Username:    data.get("nic", "username"),
		Password:    data.get("nic", "password"),
		Service:     data.get("nic", "service"),
		Domain:      data.get("nic", "domain"),
	}

	// [dns]
	cfg.DNS.CheckIntervalSec = 300
	cfg.DNS.CheckMaxAttempts = 60
	cfg.DNS.Resolver = "8.8.8.8"
	if v := data.get("dns", "check_interval_sec"); v != "" {
		cfg.DNS.CheckIntervalSec, _ = strconv.Atoi(v)
	}
	if v := data.get("dns", "check_max_attempts"); v != "" {
		cfg.DNS.CheckMaxAttempts, _ = strconv.Atoi(v)
	}
	if v := data.get("dns", "resolver"); v != "" {
		cfg.DNS.Resolver = v
	}

	// [notifier.*] sections
	for section, kv := range data {
		if strings.HasPrefix(section, "notifier.") {
			notifierType := strings.TrimPrefix(section, "notifier.")
			cfg.Notifiers[notifierType] = kv
		}
	}

	// [certificate "name"] sections
	for section, kv := range data {
		if !strings.HasPrefix(section, `certificate "`) {
			continue
		}
		name := strings.Trim(strings.TrimPrefix(section, "certificate "), `"`)

		var ports []int
		for _, ps := range splitList(kv["ports"]) {
			p, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: invalid port %q", name, ps)
			}
			ports = append(ports, p)
		}

		deploy := DeployConfig{
			Type:             kv["deploy_type"],
			PrivatePath:      kv["private_path"],
			FullchainPath:    kv["fullchain_path"],
			Commands:         splitList(kv["commands"]),
			SSHHost:          kv["ssh_host"],
			SSHUsername:      kv["ssh_username"],
			SSHKeyPath:       kv["ssh_key_path"],
			SSHPrivatePath:   kv["ssh_private_path"],
			SSHFullchainPath: kv["ssh_fullchain_path"],
		}

		cfg.Certificates = append(cfg.Certificates, CertificateConfig{
			Name:    name,
			Domains: splitList(kv["domains"]),
			Ports:   ports,
			Deploy:  deploy,
		})
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.ACME.DirectoryURL == "" {
		return fmt.Errorf("config: acme.directory_url is required")
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("config: acme.email is required")
	}
	if c.NIC.AppLogin == "" {
		return fmt.Errorf("config: nic.app_login is required")
	}
	if len(c.Certificates) == 0 {
		return fmt.Errorf("config: no certificates defined")
	}
	for _, cert := range c.Certificates {
		if len(cert.Domains) == 0 {
			return fmt.Errorf("config: certificate %q has no domains", cert.Name)
		}
		if cert.Deploy.Type != "local" && cert.Deploy.Type != "ssh" {
			return fmt.Errorf("config: certificate %q deploy_type must be 'local' or 'ssh'", cert.Name)
		}
	}
	return nil
}
