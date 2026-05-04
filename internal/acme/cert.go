package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme"
)

const (
	accountKeyBits = 2048
	certKeyBits    = 2048
)

// TXTUpdater sets the DNS TXT record required for the DNS-01 challenge.
type TXTUpdater func(domain, value string) error

// Result holds paths to the saved certificate files.
type Result struct {
	PrivatePath   string
	FullchainPath string
}

// ObtainCertificate runs the full ACME DNS-01 flow for the given domains
// and saves private.pem + fullchain.pem under outputDir/<domains[0]>.
func ObtainCertificate(
	directoryURL string,
	email string,
	domains []string,
	outputDir string,
	updateTXT TXTUpdater,
	waitTXT func(domain, value string) error,
	log *slog.Logger,
) (*Result, error) {
	ctx := context.Background()

	// Generate account key.
	accountKey, err := rsa.GenerateKey(rand.Reader, accountKeyBits)
	if err != nil {
		return nil, fmt.Errorf("acme: generate account key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
	}

	// Register account.
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		return nil, fmt.Errorf("acme: register: %w", err)
	}
	log.Info("acme: account registered", "email", email)

	// Generate certificate private key + CSR.
	certKey, err := rsa.GenerateKey(rand.Reader, certKeyBits)
	if err != nil {
		return nil, fmt.Errorf("acme: generate cert key: %w", err)
	}
	csr, err := buildCSR(certKey, domains)
	if err != nil {
		return nil, fmt.Errorf("acme: build CSR: %w", err)
	}

	// Create order.
	var ids []acme.AuthzID
	for _, d := range domains {
		ids = append(ids, acme.AuthzID{Type: "dns", Value: d})
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("acme: authorize order: %w", err)
	}
	log.Info("acme: order created", "domains", domains)

	// Complete each authorization via DNS-01.
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("acme: get authz: %w", err)
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("acme: no dns-01 challenge for %s", authz.Identifier.Value)
		}

		// DNS01ChallengeRecord returns the value to put in the TXT record.
		txtValue, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("acme: DNS01ChallengeRecord: %w", err)
		}
		log.Info("acme: setting TXT record", "domain", authz.Identifier.Value)

		if err := updateTXT(authz.Identifier.Value, txtValue); err != nil {
			return nil, fmt.Errorf("acme: update TXT: %w", err)
		}
		if err := waitTXT(authz.Identifier.Value, txtValue); err != nil {
			return nil, fmt.Errorf("acme: wait TXT: %w", err)
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("acme: accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("acme: wait authorization: %w", err)
		}
		log.Info("acme: authorization complete", "domain", authz.Identifier.Value)
	}

	// Finalize order and fetch certificate chain.
	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme: create cert: %w", err)
	}
	log.Info("acme: certificate issued")

	// Build fullchain PEM.
	var fullchainPEM []byte
	for _, der := range certDER {
		fullchainPEM = append(fullchainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	// Encode private key.
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	// Save files.
	dir := filepath.Join(outputDir, domains[0])
	result, err := saveCertificate(dir, privatePEM, fullchainPEM)
	if err != nil {
		return nil, fmt.Errorf("acme: save certificate: %w", err)
	}
	return result, nil
}

func buildCSR(key *rsa.PrivateKey, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

func saveCertificate(dir string, privatePEM, fullchainPEM []byte) (*Result, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	privatePath := filepath.Join(dir, "private.pem")
	fullchainPath := filepath.Join(dir, "fullchain.pem")

	archiveIfExists(dir, privatePath, "private.pem")
	archiveIfExists(dir, fullchainPath, "fullchain.pem")

	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(fullchainPath, fullchainPEM, 0o644); err != nil {
		return nil, err
	}
	return &Result{PrivatePath: privatePath, FullchainPath: fullchainPath}, nil
}

func archiveIfExists(dir, path, name string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	stamp := info.ModTime().UTC().Format("2006.01.02_15_04")
	archiveDir := filepath.Join(dir, "archive", stamp)
	_ = os.MkdirAll(archiveDir, 0o755)
	_ = os.Rename(path, filepath.Join(archiveDir, name))
}
