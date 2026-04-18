package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Xquik webhook payload (data shape varies by event type).
// See https://docs.xquik.com/llms.txt — Webhook Delivery.

type webhookEvent struct {
	EventType string          `json:"eventType"`
	Username  string          `json:"username"`
	Data      json.RawMessage `json:"data"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	dedup := newDeduper(4096)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/webhook/xquik", func(w http.ResponseWriter, r *http.Request) {
		handleXquikWebhook(w, r, cfg, dedup)
	})

	addr := cfg.HTTPAddr
	log.Printf("listening on %s (POST /webhook/xquik)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	HTTPAddr      string
	WebhookSecret string
	SMTP          smtpConfig
	MailFrom      string
	MailTo        []string
}

type smtpConfig struct {
	Host string
	Port int
	User string
	Pass string
}

func loadConfig() (*config, error) {
	secret := strings.TrimSpace(os.Getenv("WEBHOOK_SECRET"))
	if secret == "" {
		return nil, fmt.Errorf("WEBHOOK_SECRET is required")
	}
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		return nil, fmt.Errorf("SMTP_HOST is required")
	}
	port := 465
	if p := strings.TrimSpace(os.Getenv("SMTP_PORT")); p != "" {
		var pp int
		if _, err := fmt.Sscanf(p, "%d", &pp); err != nil || pp <= 0 {
			return nil, fmt.Errorf("invalid SMTP_PORT")
		}
		port = pp
	}
	user := strings.TrimSpace(os.Getenv("SMTP_USER"))
	pass := os.Getenv("SMTP_PASSWORD")
	if user == "" {
		return nil, fmt.Errorf("SMTP_USER is required")
	}
	from := strings.TrimSpace(os.Getenv("MAIL_FROM"))
	if from == "" {
		return nil, fmt.Errorf("MAIL_FROM is required")
	}
	toRaw := strings.TrimSpace(os.Getenv("MAIL_TO"))
	if toRaw == "" {
		return nil, fmt.Errorf("MAIL_TO is required (comma-separated addresses)")
	}
	var to []string
	for _, part := range strings.Split(toRaw, ",") {
		if a := strings.TrimSpace(part); a != "" {
			to = append(to, a)
		}
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("MAIL_TO has no valid addresses")
	}

	httpAddr := strings.TrimSpace(os.Getenv("HTTP_ADDR"))
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	return &config{
		HTTPAddr:      httpAddr,
		WebhookSecret: secret,
		SMTP: smtpConfig{
			Host: host,
			Port: port,
			User: user,
			Pass: pass,
		},
		MailFrom: from,
		MailTo:   to,
	}, nil
}

func verifySignature(payload []byte, signatureHeader, secret string) bool {
	if signatureHeader == "" || secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signatureHeader))
}

type deduper struct {
	mu   sync.Mutex
	seen map[string]struct{}
	q    []string
	cap  int
}

func newDeduper(cap int) *deduper {
	if cap < 1 {
		cap = 1024
	}
	return &deduper{seen: make(map[string]struct{}), cap: cap}
}

func (d *deduper) seenPayload(hash string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[hash]; ok {
		return true
	}
	d.seen[hash] = struct{}{}
	d.q = append(d.q, hash)
	if len(d.q) > d.cap {
		old := d.q[0]
		d.q = d.q[1:]
		delete(d.seen, old)
	}
	return false
}

func handleXquikWebhook(w http.ResponseWriter, r *http.Request, cfg *config, dedup *deduper) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Xquik-Signature")
	if !verifySignature(body, sig, cfg.WebhookSecret) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if dedup.seenPayload(hash) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("duplicate"))
		return
	}

	var ev webhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	var prettyData string
	if len(ev.Data) > 0 {
		var buf bytes.Buffer
		if err := json.Indent(&buf, ev.Data, "", "  "); err != nil {
			prettyData = string(ev.Data)
		} else {
			prettyData = buf.String()
		}
	} else {
		prettyData = "{}"
	}

	now := time.Now()
	subject, plain, html, err := renderWebhookMail(ev, prettyData, now)
	if err != nil {
		log.Printf("render mail: %v", err)
		http.Error(w, "mail render failed", http.StatusInternalServerError)
		return
	}

	if err := sendSMTPEmail(cfg.SMTP, cfg.MailFrom, cfg.MailTo, subject, plain, html); err != nil {
		log.Printf("smtp send failed: %v", err)
		http.Error(w, "mail delivery failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
