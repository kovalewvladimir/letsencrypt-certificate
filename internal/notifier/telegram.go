package notifier

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type telegram struct {
	token     string
	recipient string
	http      *http.Client
	log       *slog.Logger
}

// NewTelegram creates a Telegram notifier using the Bot API.
func NewTelegram(token, recipient string, log *slog.Logger) Notifier {
	return &telegram{
		token:     token,
		recipient: recipient,
		http:      &http.Client{Timeout: 15 * time.Second},
		log:       log,
	}
}

func (t *telegram) Send(text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)

	resp, err := t.http.PostForm(apiURL, url.Values{
		"chat_id":    {t.recipient},
		"text":       {text},
		"parse_mode": {"HTML"},
	})
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram: status %d: %s", resp.StatusCode, body)
	}
	t.log.Info("telegram: message sent")
	return nil
}
