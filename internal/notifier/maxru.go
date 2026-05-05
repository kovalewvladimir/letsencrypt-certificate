package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type maxru struct {
	accessToken string
	chatID      string
	http        *http.Client
	log         *slog.Logger
}

// NewMaxRu creates a Max.ru notifier using the platform API.
func NewMaxRu(accessToken, chatID string, log *slog.Logger) Notifier {
	return &maxru{
		accessToken: accessToken,
		chatID:      chatID,
		http:        &http.Client{Timeout: 15 * time.Second},
		log:         log,
	}
}

func (m *maxru) Send(text string) error {
	apiURL := fmt.Sprintf("https://platform-api.max.ru/messages?chat_id=%s", m.chatID)

	payload := map[string]string{
		"text":   text,
		"format": "html",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("maxru: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("maxru: %w", err)
	}

	req.Header.Set("Authorization", m.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("maxru: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("maxru: status %d: %s", resp.StatusCode, body)
	}

	m.log.Info("maxru: сообщение отправлено")
	return nil
}
