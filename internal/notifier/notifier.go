package notifier

import "log/slog"

// Notifier is the interface implemented by all notification backends.
type Notifier interface {
	Send(text string) error
}

// NewFromConfig builds a list of active Notifiers from the raw notifier map
// parsed from config (keyed by type, e.g. "telegram").
func NewFromConfig(notifiers map[string]map[string]string, log *slog.Logger) []Notifier {
	var result []Notifier

	if kv, ok := notifiers["telegram"]; ok {
		if kv["enabled"] == "false" {
			log.Info("notifier: telegram disabled via config — skipping")
		} else {
			token := kv["token"]
			recipient := kv["recipient"]
			if token != "" && recipient != "" {
				result = append(result, NewTelegram(token, recipient, log))
			} else {
				log.Warn("notifier: telegram configured but token/recipient missing — skipping")
			}
		}
	}

	return result
}

// SendAll sends text to every configured notifier, logging errors but not stopping.
func SendAll(notifiers []Notifier, text string, log *slog.Logger) {
	for _, n := range notifiers {
		if err := n.Send(text); err != nil {
			log.Error("notifier: send failed", "err", err)
		}
	}
}
