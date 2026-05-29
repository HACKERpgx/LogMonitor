# LogMonitor 🛡️

**Real-time failed login detection and multi-channel alerting for authorized security assessments.**

LogMonitor watches system authentication logs (SSH, sudo, su, FTP, mail, and more), tracks failed login attempts in a sliding time window, and sends alerts when thresholds are exceeded. Designed for penetration testers monitoring target systems during authorized engagements.

---

## Features

- **Automatic log source detection** — finds `/var/log/auth.log`, `/var/log/secure`, `/var/log/messages`, or falls back to `journalctl`
- **15+ failure patterns** — SSH, sudo, su, login, dovecot, postfix SASL, vsftpd, Dropbear, proftpd, generic PAM
- **Sliding time window** — configurable window (default 5 minutes), old entries pruned automatically
- **Multi-level alerting** — total failure threshold, per-IP threshold, watchlist usernames
- **Alert deduplication** — prevents alert storms within each time window
- **Multiple notification channels** — Console, Discord, Slack, Email, Telegram
- **Optional IP geolocation** — free geo-lookup via ip-api.com (no API key required)
- **No mandatory dependencies** — core monitor runs on stdlib only; `requests` needed for external notifications

---

## Quick Start

```bash
# Basic monitoring (auto-detects log sources)
python logmonitor.py

# Custom thresholds
python logmonitor.py --threshold 10 --window 60

# Monitor a specific log file
python logmonitor.py --log-path /var/log/secure

# Discord alerting with geolocation
python logmonitor.py \
    --threshold 5 \
    --window 300 \
    --discord https://discord.com/api/webhooks/your-webhook \
    --geo

# Telegram alerting
python logmonitor.py \
    --telegram-bot 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 \
    --telegram-chat 987654321 \
    --threshold 3

# Exclude your own scanner IP
python logmonitor.py --exclude-ip 10.10.10.5 --threshold 5

# Load config from JSON file
python logmonitor.py --config myconfig.json
