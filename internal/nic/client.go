package nic

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	oauthURL = "https://api.nic.ru/oauth/token"
	baseURL  = "https://api.nic.ru/dns-master"
)

// Client manages NIC.RU DNS API access.
type Client struct {
	appLogin    string
	appPassword string
	tokenFile   string
	token       string
	http        *http.Client
	log         *slog.Logger
}

func New(appLogin, appPassword, tokenFile string, log *slog.Logger) *Client {
	return &Client{
		appLogin:    appLogin,
		appPassword: appPassword,
		tokenFile:   tokenFile,
		http:        &http.Client{Timeout: 30 * time.Second},
		log:         log,
	}
}

// Authorize fetches or loads a cached OAuth2 Bearer token.
func (c *Client) Authorize(username, password string) error {
	if cached, ok := c.loadToken(); ok {
		c.token = cached
		c.log.Info("nic: loaded token from cache")
		return nil
	}
	return c.fetchToken(username, password)
}

func (c *Client) loadToken() (string, bool) {
	if c.tokenFile == "" {
		return "", false
	}
	data, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", false
	}
	var tc tokenCache
	if err := json.Unmarshal(data, &tc); err != nil {
		return "", false
	}
	if time.Now().Unix() >= tc.CreatedAt+int64(tc.ExpiresIn) {
		c.log.Info("nic: cached token expired")
		return "", false
	}
	return tc.AccessToken, true
}

func (c *Client) fetchToken(username, password string) error {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      {`.+:/dns-master/.+`},
	}
	req, err := http.NewRequest(http.MethodPost, oauthURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("nic oauth: %w", err)
	}
	req.SetBasicAuth(c.appLogin, c.appPassword)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("nic oauth: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nic oauth: status %d: %s", resp.StatusCode, body)
	}

	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("nic oauth: parse response: %w", err)
	}
	c.token = tok.AccessToken

	if c.tokenFile != "" {
		tc := tokenCache{
			AccessToken: tok.AccessToken,
			TokenType:   tok.TokenType,
			ExpiresIn:   tok.ExpiresIn,
			CreatedAt:   time.Now().Unix(),
		}
		if b, err := json.Marshal(tc); err == nil {
			_ = os.WriteFile(c.tokenFile, b, 0o600)
		}
	}
	c.log.Info("nic: obtained new token")
	return nil
}

func (c *Client) do(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/xml; charset=UTF-8")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nic %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nic %s %s: status %d: %s", method, path, resp.StatusCode, b)
	}
	return b, nil
}

// GetRecords returns all DNS records for the given service/zone.
func (c *Client) GetRecords(service, zone string) ([]rrEntry, error) {
	path := fmt.Sprintf("/services/%s/zones/%s/records", service, zone)
	body, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var r response
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("nic: parse records: %w", err)
	}
	return r.Data.Zone.Records, nil
}

// AddTXTRecord creates a TXT record in the given service/zone.
func (c *Client) AddTXTRecord(service, zone, name, value string, ttl int) error {
	req := addRecordRequest{
		RRList: []txtRR{{Name: name, TTL: ttl, Type: "TXT", TXT: value}},
	}
	xmlBody, err := xml.Marshal(req)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/services/%s/zones/%s/records", service, zone)
	_, err = c.do(http.MethodPut, path, bytes.NewReader(xmlBody))
	if err != nil {
		return err
	}
	c.log.Info("nic: TXT record added", "name", name)
	return nil
}

// DeleteRecord removes a DNS record by ID.
func (c *Client) DeleteRecord(id int, service, zone string) error {
	path := fmt.Sprintf("/services/%s/zones/%s/records/%d", service, zone, id)
	_, err := c.do(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	c.log.Info("nic: record deleted", "id", id)
	return nil
}

// Commit applies pending changes to the DNS zone.
func (c *Client) Commit(service, zone string) error {
	path := fmt.Sprintf("/services/%s/zones/%s/commit", service, zone)
	_, err := c.do(http.MethodPost, path, nil)
	if err != nil {
		return err
	}
	c.log.Info("nic: zone committed", "service", service, "zone", zone)
	return nil
}

// UpdateTXTRecord replaces any existing TXT record with the given name,
// then commits the zone. This is what the ACME flow calls.
func (c *Client) UpdateTXTRecord(service, zone, name, value string) error {
	records, err := c.GetRecords(service, zone)
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Type == "TXT" && r.Name == name {
			c.log.Info("nic: deleting old TXT record", "id", r.ID, "name", r.Name)
			if err := c.DeleteRecord(r.ID, service, zone); err != nil {
				return err
			}
		}
	}
	if err := c.AddTXTRecord(service, zone, name, value, 1); err != nil {
		return err
	}
	return c.Commit(service, zone)
}
