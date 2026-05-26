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
	"strconv"
	"strings"
	"sync"
	"time"
)

const fiveMinutesMs = int64(5 * 60 * 1000)

var seenNonces sync.Map

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

	dedupCap := 4096
	dedup := newDeduper(dedupCap)
	logStartup(cfg, dedupCap)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			log.Printf("health: method not allowed method=%s path=%s %s", r.Method, r.URL.Path, requestClientDesc(r))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if logHealthEnabled() {
			log.Printf("health: ok %s", requestClientDesc(r))
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

func logStartup(cfg *config, dedupCap int) {
	tlsMode := "implicit_tls"
	if cfg.SMTP.Port != 465 {
		tlsMode = "starttls_if_supported"
	}
	log.Printf(
		"startup: http_addr=%s webhook_secret_configured=yes smtp_host=%s smtp_port=%d tls_mode=%s smtp_user=%s mail_from=%s recipients=%d dedup_cap=%d",
		cfg.HTTPAddr,
		cfg.SMTP.Host,
		cfg.SMTP.Port,
		tlsMode,
		cfg.SMTP.User,
		cfg.MailFrom,
		len(cfg.MailTo),
		dedupCap,
	)
}

func logHealthEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_HEALTH")))
	return v == "1" || v == "true" || v == "yes"
}

func requestClientDesc(r *http.Request) string {
	ff := r.Header.Get("X-Forwarded-For")
	ri := r.Header.Get("X-Real-IP")
	ua := r.Header.Get("User-Agent")
	if len(ua) > 200 {
		ua = ua[:200] + "…"
	}
	return fmt.Sprintf("remote=%s x_forwarded_for=%q x_real_ip=%q ua=%q", r.RemoteAddr, ff, ri, ua)
}

func verifyWebhook(payload []byte, headers http.Header, secret string) bool {
	timestamp := headers.Get("X-Xquik-Timestamp")
	nonce := headers.Get("X-Xquik-Nonce")
	signature := headers.Get("X-Xquik-Signature")
	if timestamp == "" || nonce == "" || signature == "" || secret == "" {
		return false
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	nowMs := time.Now().UnixMilli()
	diff := nowMs - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > fiveMinutesMs {
		return false
	}

	seenNonces.Range(func(key, value any) bool {
		expiresAt, ok := value.(int64)
		if ok && expiresAt <= nowMs {
			seenNonces.Delete(key)
		}
		return true
	})
	if _, replayed := seenNonces.LoadOrStore(nonce, nowMs+fiveMinutesMs); replayed {
		return false
	}

	signingString := fmt.Sprintf("%s.%s.%s", timestamp, nonce, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingString))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
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
		log.Printf("webhook: method not allowed method=%s path=%s %s", r.Method, r.URL.Path, requestClientDesc(r))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	t0 := time.Now()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		log.Printf("webhook: read body: %v %s", err, requestClientDesc(r))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("webhook: incoming bytes=%d %s", len(body), requestClientDesc(r))

	if !verifyWebhook(body, r.Header, cfg.WebhookSecret) {
		log.Printf(
			"webhook: invalid signature ts_present=%v nonce_present=%v sig_present=%v %s",
			r.Header.Get("X-Xquik-Timestamp") != "",
			r.Header.Get("X-Xquik-Nonce") != "",
			r.Header.Get("X-Xquik-Signature") != "",
			requestClientDesc(r),
		)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if dedup.seenPayload(hash) {
		log.Printf("webhook: duplicate payload_hash_prefix=%s %s", hash[:16], requestClientDesc(r))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("duplicate"))
		return
	}

	var ev webhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		log.Printf("webhook: json unmarshal: %v body_bytes=%d %s", err, len(body), requestClientDesc(r))
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
		log.Printf("webhook: render mail failed eventType=%q username=%q: %v", ev.EventType, ev.Username, err)
		http.Error(w, "mail render failed", http.StatusInternalServerError)
		return
	}

	log.Printf(
		"webhook: sending mail eventType=%q username=%q subject=%q smtp=%s:%d",
		ev.EventType,
		ev.Username,
		subject,
		cfg.SMTP.Host,
		cfg.SMTP.Port,
	)

	if err := sendSMTPEmail(cfg.SMTP, cfg.MailFrom, cfg.MailTo, subject, plain, html); err != nil {
		log.Printf("webhook: smtp send failed eventType=%q username=%q: %v", ev.EventType, ev.Username, err)
		http.Error(w, "mail delivery failed", http.StatusInternalServerError)
		return
	}

	log.Printf(
		"webhook: ok eventType=%q username=%q elapsed=%s",
		ev.EventType,
		ev.Username,
		time.Since(t0).Truncate(time.Millisecond),
	)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
