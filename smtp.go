package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

func sendSMTPEmail(cfg smtpConfig, from string, to []string, subject, body string) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	if ok, _ := client.Extension("AUTH"); ok {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt %s: %w", rcpt, err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	msg := buildRFC822Message(from, to, subject, body)
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("quit: %w", err)
	}
	return nil
}

func buildRFC822Message(from string, to []string, subject, body string) []byte {
	subjEnc := mimeEncodeHeader(subject)
	bodyB64 := base64.StdEncoding.EncodeToString([]byte(body))
	var b strings.Builder
	b.WriteString(fmt.Sprintf("From: %s\r\n", from))
	b.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	b.WriteString(fmt.Sprintf("Subject: %s\r\n", subjEnc))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	// Wrap base64 at 76 columns for RFC 2045.
	const lineLen = 76
	for i := 0; i < len(bodyB64); i += lineLen {
		end := i + lineLen
		if end > len(bodyB64) {
			end = len(bodyB64)
		}
		b.WriteString(bodyB64[i:end])
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func mimeEncodeHeader(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(s)))
}
