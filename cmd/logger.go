package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// multiHandler fans out log records to multiple slog.Handler instances.
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(handlers ...slog.Handler) slog.Handler {
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: next}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: next}
}

// httpHandler sends each log record as an HTTP POST (form-encoded) to a remote server.
// Sending is asynchronous: records are placed into a buffered channel and dispatched
// by a background goroutine, so logging never blocks the caller.
type httpHandler struct {
	queue    chan string  // shared across WithAttrs clones
	client   *http.Client // shared across WithAttrs clones
	url      string       // shared across WithAttrs clones
	level    slog.Level
	certName string // captured from slog attr "cert"
	debug    bool
}

func newHTTPHandler(rawURL string, level slog.Level, timeoutSec int, debug bool) *httpHandler {
	h := &httpHandler{
		queue:    make(chan string, 256),
		client:   &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
		url:      rawURL,
		level:    level,
		certName: "main",
		debug:    debug,
	}
	go h.worker()
	return h
}

func (h *httpHandler) worker() {
	for line := range h.queue {
		data := url.Values{
			"t":       {line},
			"no_date": {"true"},
		}
		resp, err := h.client.PostForm(h.url, data)
		if err != nil {
			if h.debug {
				slog.Debug("http logger: post failed", "err", err)
			}
			continue
		}
		resp.Body.Close()
	}
}

func (h *httpHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *httpHandler) Handle(_ context.Context, r slog.Record) error {
	// Format: "2006-01-02 15:04:05\tcertName:\tLEVEL:\tmessage key=val ..."
	var sb strings.Builder
	sb.WriteString(r.Time.Format("2006-01-02 15:04:05"))
	sb.WriteByte('\t')
	sb.WriteString(h.certName)
	sb.WriteString("\t")
	sb.WriteString(r.Level.String())
	sb.WriteString(":\t")
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteByte(' ')
		sb.WriteString(a.Key)
		sb.WriteByte('=')
		sb.WriteString(fmt.Sprint(a.Value.Any()))
		return true
	})

	line := sb.String()
	select {
	case h.queue <- line:
	default:
		if h.debug {
			slog.Debug("http logger: queue full, dropping record")
		}
	}
	return nil
}

// WithAttrs creates a clone of the handler. If attrs contain key "cert", it is
// captured as the thread name used in the log line format.
func (h *httpHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	for _, a := range attrs {
		if a.Key == "cert" {
			clone.certName = fmt.Sprint(a.Value.Any())
		}
	}
	return &clone
}

func (h *httpHandler) WithGroup(_ string) slog.Handler { return h }
