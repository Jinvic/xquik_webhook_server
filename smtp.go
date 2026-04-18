package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
)

const smtpImplicitTLS = 465

func sendSMTPEmail(cfg smtpConfig, from string, to []string, subject, plainBody, htmlBody string) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	log.Printf("smtp: dial addr=%s implicit_tls=%v", addr, cfg.Port == smtpImplicitTLS)

	var conn net.Conn
	var err error
	if cfg.Port == smtpImplicitTLS {
		tlsCfg := &tls.Config{ServerName: serverNameForTLS(cfg.Host)}
		conn, err = tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("tls dial smtp: %w", err)
		}
	} else {
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("dial smtp: %w", err)
		}
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if cfg.Port != smtpImplicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: serverNameForTLS(cfg.Host)}
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
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
	msg, err := buildMultipartMessage(from, to, subject, plainBody, htmlBody)
	if err != nil {
		_ = wc.Close()
		return err
	}
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

func serverNameForTLS(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func buildMultipartMessage(from string, to []string, subject, plainBody, htmlBody string) ([]byte, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	writePart := func(h textproto.MIMEHeader, content string) error {
		pw, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		return writeBase64Lines(pw, content)
	}

	ph := make(textproto.MIMEHeader)
	ph.Set("Content-Type", "text/plain; charset=UTF-8")
	ph.Set("Content-Transfer-Encoding", "base64")
	if err := writePart(ph, plainBody); err != nil {
		return nil, err
	}

	hh := make(textproto.MIMEHeader)
	hh.Set("Content-Type", "text/html; charset=UTF-8")
	hh.Set("Content-Transfer-Encoding", "base64")
	if err := writePart(hh, htmlBody); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	subjEnc := encodeSubjectHeader(subject)
	var out strings.Builder
	out.WriteString(fmt.Sprintf("From: %s\r\n", from))
	out.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	out.WriteString(fmt.Sprintf("Subject: %s\r\n", subjEnc))
	out.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&out, "Content-Type: multipart/alternative; boundary=%s\r\n", mw.Boundary())
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return []byte(out.String()), nil
}

func writeBase64Lines(w io.Writer, s string) error {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	const lineLen = 76
	for i := 0; i < len(enc); i += lineLen {
		end := i + lineLen
		if end > len(enc) {
			end = len(enc)
		}
		if _, err := io.WriteString(w, enc[i:end]); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	}
	return nil
}

func encodeSubjectHeader(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(s)))
		}
	}
	return s
}
