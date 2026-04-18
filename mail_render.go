package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

type webhookMailView struct {
	EventType   string
	Username    string
	TimeUTC     string
	PrettyJSON  string
	EventAccent string
}

var webhookHTMLTpl = template.Must(template.New("xquik").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xquik 通知</title>
</head>
<body style="margin:0;padding:0;background:#0f1419;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#0f1419;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px;background:#15202b;border-radius:12px;overflow:hidden;border:1px solid #38444d;box-shadow:0 8px 32px rgba(0,0,0,.35);">
          <tr>
            <td style="background:linear-gradient(135deg,#1d9bf0 0%,#7856ff 100%);padding:20px 24px;">
              <div style="color:#fff;font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.9;">Xquik Webhook</div>
              <div style="color:#fff;font-size:20px;font-weight:700;margin-top:6px;line-height:1.3;">新事件已送达</div>
            </td>
          </tr>
          <tr>
            <td style="padding:22px 24px 8px;">
              <span style="display:inline-block;padding:4px 10px;border-radius:999px;background:{{.EventAccent}}22;color:{{.EventAccent}};font-size:12px;font-weight:600;">{{.EventType}}</span>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 24px 0;color:#e7e9ea;font-size:15px;line-height:1.6;">
              <strong style="color:#f7f9f9;">@{{.Username}}</strong>
              <span style="color:#8b98a5;"> · 监控账号</span>
            </td>
          </tr>
          <tr>
            <td style="padding:12px 24px 0;color:#8b98a5;font-size:12px;">{{.TimeUTC}}</td>
          </tr>
          <tr>
            <td style="padding:18px 24px 24px;">
              <div style="background:#192734;border:1px solid #38444d;border-radius:8px;padding:14px 16px;">
                <div style="color:#8b98a5;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">Payload · data</div>
                <pre style="margin:0;color:#d0d8e0;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">{{.PrettyJSON}}</pre>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding:0 24px 20px;color:#536471;font-size:11px;line-height:1.5;border-top:1px solid #38444d;">
              <p style="margin:16px 0 0;">由 Xquik 实时推送 · 请勿直接回复此邮件</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`))

func eventAccentColor(eventType string) string {
	switch {
	case strings.HasPrefix(eventType, "tweet."):
		return "#1d9bf0"
	case strings.HasPrefix(eventType, "follower."):
		return "#00ba7c"
	case strings.HasSuffix(eventType, ".completed"):
		return "#f7931a"
	case strings.HasSuffix(eventType, ".failed"):
		return "#f4212e"
	default:
		return "#7856ff"
	}
}

func renderWebhookMail(ev webhookEvent, prettyJSON string, t time.Time) (subject string, plain string, html string, err error) {
	subject = fmt.Sprintf("[Xquik] %s — @%s", ev.EventType, ev.Username)
	plain = fmt.Sprintf(
		"事件类型: %s\n监控用户: @%s\n时间(UTC): %s\n\n--- data ---\n%s\n",
		ev.EventType,
		ev.Username,
		t.UTC().Format(time.RFC3339),
		prettyJSON,
	)
	view := webhookMailView{
		EventType:   ev.EventType,
		Username:    ev.Username,
		TimeUTC:     t.UTC().Format(time.RFC3339) + " UTC",
		PrettyJSON:  prettyJSON,
		EventAccent: eventAccentColor(ev.EventType),
	}
	var buf bytes.Buffer
	if err := webhookHTMLTpl.Execute(&buf, view); err != nil {
		return "", "", "", err
	}
	html = buf.String()
	return subject, plain, html, nil
}
