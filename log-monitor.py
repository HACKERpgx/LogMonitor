#!/usr/bin/env python3
"""
LogMonitor - Failed Login Attempt Detector & Notifier
Authorized Penetration Testing Utility
Monitors auth logs for brute-force/login spraying attempts and alerts via multiple channels.
"""

import os
import re
import time
import json
import argparse
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Thread, Event
from typing import Optional

# --- Notification Imports (conditional) ---
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import smtplib
    from email.message import EmailMessage
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_CONFIG = {
    # Threshold: trigger alert after N failed attempts
    "threshold": 5,

    # Time window (seconds) to count failures
    "time_window": 300,  # 5 minutes

    # Paths to monitor (auto-detected on Linux if None)
    "log_paths": None,

    # Poll interval (seconds)
    "poll_interval": 5,

    # Notifications
    "notify_discord": False,
    "discord_webhook_url": "",

    "notify_slack": False,
    "slack_webhook_url": "",

    "notify_email": False,
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_tls": True,
    "smtp_user": "",
    "smtp_pass": "",
    "email_from": "",
    "email_to": "",

    "notify_telegram": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",

    # Console output
    "verbose": True,

    # Track unique IPs vs total count
    "track_per_ip": True,
    "threshold_per_ip": 3,

    # Watchlist - always alert on these usernames
    "watchlist_usernames": ["root", "admin", "administrator"],

    # Exclude specific IPs (e.g. your own scanner)
    "exclude_ips": [],

    # Geolookup (free, uses ip-api.com)
    "geo_lookup": False,
}


def detect_log_paths():
    """Auto-detect auth log locations."""
    candidates = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/journal",
    ]
    for p in candidates:
        if os.path.exists(p):
            return [p]

    # Try journalctl
    try:
        subprocess.run(["journalctl", "--version"], capture_output=True, check=True)
        return ["journalctl"]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return []


# =============================================================================
# Log Parser
# =============================================================================

FAILURE_PATTERNS = [
    # SSH failures
    re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'),
    re.compile(r'Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)'),
    re.compile(r'Connection closed by authenticating user (?P<user>\S+) (?P<ip>[\d.]+)'),
    re.compile(r'Connection reset by (?P<ip>[\d.]+) port \d+'),
    # sudo failures
    re.compile(r'pam_unix\(sudo:auth\): authentication failure.*?user=(?P<user>\S+)'),
    # login failures
    re.compile(r'pam_unix\(sshd:auth\): authentication failure.*?rhost=(?P<ip>[\d.]+)'),
    re.compile(r'pam_unix\(login:auth\): authentication failure.*?user=(?P<user>\S+)'),
    re.compile(r'authentication failure;.*?rhost=(?P<ip>[\d.]+)'),
    # su failures
    re.compile(r'pam_unix\(su:auth\): authentication failure.*?user=(?P<user>\S+)'),
    # dovecot / mail
    re.compile(r'pam_unix\(dovecot:auth\): authentication failure.*?user=(?P<user>\S+)'),
    # postfix/sasl
    re.compile(r'sasl_username=(?P<user>\S+) authentication failed'),
    # FTP
    re.compile(r'pam_unix\(vsftpd:auth\): authentication failure.*?user=(?P<user>\S+)'),
    # WinRM / RDP via journal
    re.compile(r'Failed login for (?P<user>\S+) from (?P<ip>[\d.]+)'),
    # Generic pam failure
    re.compile(r'pam_unix\([^)]+\): authentication failure.*?user=(?P<user>\S+)'),
    # kex / algorithm negotiation failures (SSH scanning)
    re.compile(r'Unable to negotiate with (?P<ip>[\d.]+)'),
    # Dropbear SSH
    re.compile(r'Bad password attempt for (?P<user>\S+) from (?P<ip>[\d.]+)'),
    # SSHD disconnects pre-auth
    re.compile(r'Did not receive identification string from (?P<ip>[\d.]+)'),
    # FTP proftpd
    re.compile(r'proftpd:.*?\((?P<ip>[\d.]+)\):.*?USER (?P<user>\S+): Login incorrect'),
]


def parse_line(line: str) -> Optional[dict]:
    """Extract failed login info from a log line."""
    for pattern in FAILURE_PATTERNS:
        m = pattern.search(line)
        if m:
            result = m.groupdict()
            result["raw"] = line.strip()
            result["timestamp"] = datetime.now().isoformat()
            return result
    return None


def get_journal_lines(since: str = "1 min ago") -> list:
    """Pull recent failed auth entries from journalctl."""
    try:
        cmd = [
            "journalctl",
            "-u", "sshd",
            "-u", "systemd-logind",
            "-u", "sudo",
            "--since", since,
            "--no-pager",
            "-p", "err",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.splitlines()
    except Exception:
        return []


def follow_file(filepath: str, stop_event: Event):
    """Generator that yields new lines from a file (tail -f)."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # go to end
        while not stop_event.is_set():
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)


# =============================================================================
# Notifiers
# =============================================================================

class Notifier:
    def __init__(self, config: dict):
        self.config = config

    def send(self, subject: str, message: str):
        raise NotImplementedError


class ConsoleNotifier(Notifier):
    def send(self, subject: str, message: str):
        banner = f"{'='*60}\n[!] ALERT: {subject}\n{'='*60}"
        print(f"\n{banner}\n{message}\n{'='*60}\n")


class DiscordNotifier(Notifier):
    def send(self, subject: str, message: str):
        if not HAS_REQUESTS:
            return
        url = self.config["discord_webhook_url"]
        if not url:
            return
        payload = {
            "embeds": [{
                "title": f"🚨 {subject}",
                "description": message,
                "color": 0xFF0000,
                "timestamp": datetime.utcnow().isoformat(),
            }]
        }
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            print(f"[!] Discord notify failed: {e}")


class SlackNotifier(Notifier):
    def send(self, subject: str, message: str):
        if not HAS_REQUESTS:
            return
        url = self.config["slack_webhook_url"]
        if not url:
            return
        payload = {
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*🚨 {subject}*\n{message}"}}
            ]
        }
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            print(f"[!] Slack notify failed: {e}")


class EmailNotifier(Notifier):
    def send(self, subject: str, message: str):
        if not HAS_SMTP:
            return
        cfg = self.config
        msg = EmailMessage()
        msg.set_content(message)
        msg["Subject"] = subject
        msg["From"] = cfg["email_from"]
        msg["To"] = cfg["email_to"]
        try:
            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as s:
                if cfg["smtp_tls"]:
                    s.starttls()
                if cfg["smtp_user"]:
                    s.login(cfg["smtp_user"], cfg["smtp_pass"])
                s.send_message(msg)
        except Exception as e:
            print(f"[!] Email notify failed: {e}")


class TelegramNotifier(Notifier):
    def send(self, subject: str, message: str):
        if not HAS_REQUESTS:
            return
        token = self.config["telegram_bot_token"]
        chat_id = self.config["telegram_chat_id"]
        if not token or not chat_id:
            return
        text = f"🚨 *{subject}*\n\n{message}"
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            requests.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}, timeout=10)
        except Exception as e:
            print(f"[!] Telegram notify failed: {e}")


class GeoLookup:
    """Minimal free IP geolocation."""

    def __init__(self):
        self.cache = {}

    def lookup(self, ip: str) -> str:
        if ip in self.cache:
            return self.cache[ip]
        if not HAS_REQUESTS:
            return ""
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp", timeout=5)
            if r.status_code == 200:
                data = r.json()
                parts = [data.get("city", ""), data.get("regionName", ""), data.get("country", "")]
                isp = data.get("isp", "")
                loc = ", ".join(p for p in parts if p)
                if isp:
                    loc += f" [{isp}]"
                self.cache[ip] = loc if loc else "N/A"
                return self.cache[ip]
        except Exception:
            pass
        self.cache[ip] = "Unknown"
        return "Unknown"


# =============================================================================
# Main Monitor
# =============================================================================

class AuthLogMonitor:
    def __init__(self, config: dict = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.stop_event = Event()

        # Auto-detect log paths
        if not self.config["log_paths"]:
            self.config["log_paths"] = detect_log_paths()

        # Tracking
        self.failures = deque()  # (timestamp, ip, user, raw)
        self.ip_counter = defaultdict(int)
        self.user_counter = defaultdict(int)
        self.ip_user_map = defaultdict(lambda: defaultdict(int))
        self.alerted = set()  # dedup alerts

        # Notifiers
        self.notifiers = []
        self._setup_notifiers()

        # Geolocator
        self.geo = GeoLookup() if self.config["geo_lookup"] else None

        # Logger
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        self.log = logging.getLogger("LogMonitor")

    def _setup_notifiers(self):
        self.notifiers.append(ConsoleNotifier(self.config))
        if self.config["notify_discord"] and self.config["discord_webhook_url"]:
            self.notifiers.append(DiscordNotifier(self.config))
        if self.config["notify_slack"] and self.config["slack_webhook_url"]:
            self.notifiers.append(SlackNotifier(self.config))
        if self.config["notify_email"] and self.config["email_to"]:
            self.notifiers.append(EmailNotifier(self.config))
        if self.config["notify_telegram"] and self.config["telegram_bot_token"]:
            self.notifiers.append(TelegramNotifier(self.config))

    def _prune_old(self):
        """Remove entries outside the time window."""
        cutoff = time.time() - self.config["time_window"]
        while self.failures and self.failures[0][0] < cutoff:
            old = self.failures.popleft()
            ip, user = old[1], old[2]
            self.ip_counter[ip] -= 1
            self.user_counter[user] -= 1
            self.ip_user_map[ip][user] -= 1
            if self.ip_counter[ip] <= 0:
                del self.ip_counter[ip]
            if self.user_counter[user] <= 0:
                del self.user_counter[user]

    def _get_alert_key(self, alert_type: str, key: str):
        return f"{alert_type}:{key}"

    def _should_alert(self, key: str) -> bool:
        if key in self.alerted:
            return False
        self.alerted.add(key)
        # Auto-expire after twice the time window
        Thread(target=lambda: self.alerted.discard(key) or time.sleep(self.config["time_window"] * 2)).start()
        return True

    def process_events(self, events: list):
        now = time.time()
        for event in events:
            ip = event.get("ip", "0.0.0.0")
            user = event.get("user", "unknown")

            if ip in self.config["exclude_ips"]:
                continue

            self.failures.append((now, ip, user, event["raw"]))
            self.ip_counter[ip] += 1
            self.user_counter[user] += 1
            self.ip_user_map[ip][user] += 1

            if self.config["verbose"]:
                self.log.info(f"[FAIL] {user}@{ip} - {event['raw'][:100]}")

        self._prune_old()

        # Check thresholds
        self._check_thresholds()

    def _check_thresholds(self):
        """Evaluate alert conditions."""

        # 1. Total failures across all IPs
        total = sum(self.ip_counter.values())
        if total >= self.config["threshold"]:
            key = self._get_alert_key("total", str(int(time.time() / self.config["time_window"])))
            if self._should_alert(key):
                self._trigger_alert(
                    f"High-volume login failures: {total} attempts in {self.config['time_window']}s",
                    self._build_summary()
                )

        # 2. Per-IP threshold
        for ip, count in self.ip_counter.items():
            if count >= self.config["threshold_per_ip"]:
                key = self._get_alert_key("ip", ip)
                if self._should_alert(key):
                    users = ", ".join(
                        f"{u}({c})" for u, c in self.ip_user_map[ip].items() if c > 0
                    )
                    geo = f" [{self.geo.lookup(ip)}]" if self.geo else ""
                    self._trigger_alert(
                        f"Brute force from {ip}{geo} — {count} attempts",
                        f"Target users: {users}"
                    )

        # 3. Watchlist usernames
        for user in self.config["watchlist_usernames"]:
            if user in self.user_counter and self.user_counter[user] >= 1:
                ips = ", ".join(
                    ip for ip, users in self.ip_user_map.items()
                    if user in users and users[user] > 0
                )
                key = self._get_alert_key("watch", f"{user}:{int(time.time()/60)}")
                if self._should_alert(key):
                    self._trigger_alert(
                        f"Watchlist user '{user}' targeted ({self.user_counter[user]} failures)",
                        f"Source IPs: {ips}"
                    )

    def _build_summary(self) -> str:
        """Build alert message body."""
        lines = [f"📊 Failed Login Summary (last {self.config['time_window']}s):"]
        lines.append(f"{'─'*50}")
        lines.append(f"Total failures: {sum(self.ip_counter.values())}")
        lines.append(f"Unique source IPs: {len(self.ip_counter)}")
        lines.append(f"Unique target users: {len(self.user_counter)}")
        lines.append("")
        lines.append("Top source IPs:")
        for ip, count in sorted(self.ip_counter.items(), key=lambda x: -x[1])[:10]:
            geo = f" ({self.geo.lookup(ip)})" if self.geo else ""
            lines.append(f"  {ip:<18} {count:>4} attempts{geo}")
        lines.append("")
        lines.append("Top target users:")
        for user, count in sorted(self.user_counter.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {user:<15} {count:>4} attempts")
        return "\n".join(lines)

    def _trigger_alert(self, subject: str, message: str):
        for notifier in self.notifiers:
            try:
                notifier.send(subject, message)
            except Exception as e:
                self.log.error(f"Notifier failed: {e}")

    def run(self):
        """Main monitoring loop."""
        log_paths = self.config["log_paths"]

        if not log_paths:
            self.log.error("No log files found. Try specifying --log-path manually.")
            return

        self.log.info(f"🔍 Monitoring {len(log_paths)} source(s): {log_paths}")
        self.log.info(f"⚙️  Threshold: {self.config['threshold']} attempts in {self.config['time_window']}s")
        self.log.info(f"📢 Notifiers: {[n.__class__.__name__ for n in self.notifiers]}")
        self.log.info("Listening... (Ctrl+C to stop)\n")

        if "journalctl" in log_paths:
            self._run_journal()
        else:
            self._run_file_monitor()

    def _run_file_monitor(self):
        """Monitor static log files."""
        threads = []
        for path in self.config["log_paths"]:
            if not os.path.exists(path):
                self.log.warning(f"Path not found: {path}")
                continue
            t = Thread(target=self._monitor_file, args=(path,), daemon=True)
            t.start()
            threads.append(t)

        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()
            self.log.info("Shutting down.")

    def _monitor_file(self, path: str):
        for line in follow_file(path, self.stop_event):
            parsed = parse_line(line)
            if parsed:
                self.process_events([parsed])

    def _run_journal(self):
        """Monitor journald for new entries."""
        try:
            while not self.stop_event.is_set():
                lines = get_journal_lines(since="30 seconds ago")
                for line in lines:
                    parsed = parse_line(line)
                    if parsed:
                        self.process_events([parsed])
                time.sleep(self.config["poll_interval"])
        except KeyboardInterrupt:
            self.stop_event.set()
            self.log.info("Shutting down.")


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="LogMonitor - Failed Login Detector & Notifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic monitoring with console output
  python logmonitor.py

  # Custom threshold and time window
  python logmonitor.py --threshold 10 --window 60

  # Monitor a specific log file
  python logmonitor.py --log-path /var/log/secure

  # Discord alerts
  python logmonitor.py --discord https://discord.com/api/webhooks/...

  # Full alerting stack
  python logmonitor.py \\
      --threshold 5 \\
      --window 300 \\
      --discord https://discord.com/api/webhooks/... \\
      --telegram-bot 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 \\
      --telegram-chat 987654321 \\
      --geo \\
      --exclude-ip 192.168.1.100
        """
    )

    # Monitoring options
    parser.add_argument("--log-path", action="append", dest="log_paths",
                        help="Specific log file to monitor (can be used multiple times)")
    parser.add_argument("--threshold", type=int, default=DEFAULT_CONFIG["threshold"],
                        help=f"Alert after total failures (default: {DEFAULT_CONFIG['threshold']})")
    parser.add_argument("--threshold-per-ip", type=int, default=DEFAULT_CONFIG["threshold_per_ip"],
                        help=f"Alert after per-IP failures (default: {DEFAULT_CONFIG['threshold_per_ip']})")
    parser.add_argument("--window", type=int, default=DEFAULT_CONFIG["time_window"],
                        help=f"Time window in seconds (default: {DEFAULT_CONFIG['time_window']})")
    parser.add_argument("--poll-interval", type=int, default=DEFAULT_CONFIG["poll_interval"],
                        help=f"Poll interval in seconds (default: {DEFAULT_CONFIG['poll_interval']})")
    parser.add_argument("--exclude-ip", action="append", dest="exclude_ips", default=[],
                        help="Exclude an IP from triggering alerts")
    parser.add_argument("--watchlist", action="append", dest="watchlist", default=[],
                        help="Usernames to always alert on (e.g. root)")
    parser.add_argument("--geo", action="store_true", dest="geo_lookup",
                        help="Enable IP geolocation (uses free ip-api.com)")

    # Discord
    parser.add_argument("--discord", dest="discord_webhook_url", default="",
                        help="Discord webhook URL")
    parser.add_argument("--discord-enable", dest="notify_discord", action="store_true",
                        help="Enable Discord notifications")

    # Slack
    parser.add_argument("--slack", dest="slack_webhook_url", default="",
                        help="Slack webhook URL")
    parser.add_argument("--slack-enable", dest="notify_slack", action="store_true",
                        help="Enable Slack notifications")

    # Email
    parser.add_argument("--email-server", dest="smtp_server", default="")
    parser.add_argument("--email-port", dest="smtp_port", type=int, default=587)
    parser.add_argument("--email-user", dest="smtp_user", default="")
    parser.add_argument("--email-pass", dest="smtp_pass", default="")
    parser.add_argument("--email-from", dest="email_from", default="")
    parser.add_argument("--email-to", dest="email_to", default="")
    parser.add_argument("--email-enable", dest="notify_email", action="store_true",
                        help="Enable email notifications")

    # Telegram
    parser.add_argument("--telegram-bot", dest="telegram_bot_token", default="")
    parser.add_argument("--telegram-chat", dest="telegram_chat_id", default="")
    parser.add_argument("--telegram-enable", dest="notify_telegram", action="store_true",
                        help="Enable Telegram notifications")

    # Other
    parser.add_argument("--quiet", action="store_true", dest="quiet",
                        help="Suppress verbose per-event logging")
    parser.add_argument("--config", help="Load config from JSON file")

    args = parser.parse_args()

    # Build config
    config = {}

    # Load from file first, then CLI overrides
    if args.config:
        with open(args.config) as f:
            config.update(json.load(f))

    # CLI overrides
    if args.log_paths:
        config["log_paths"] = args.log_paths
    if args.threshold:
        config["threshold"] = args.threshold
    if args.threshold_per_ip:
        config["threshold_per_ip"] = args.threshold_per_ip
    if args.window:
        config["time_window"] = args.window
    if args.poll_interval:
        config["poll_interval"] = args.poll_interval
    if args.exclude_ips:
        config["exclude_ips"] = args.exclude_ips
    if args.watchlist:
        config["watchlist_usernames"] = args.watchlist
    if args.geo_lookup:
        config["geo_lookup"] = True
    if args.discord_webhook_url:
        config["discord_webhook_url"] = args.discord_webhook_url
        config["notify_discord"] = args.notify_discord or True
    if args.notify_discord:
        config["notify_discord"] = True
    if args.slack_webhook_url:
        config["slack_webhook_url"] = args.slack_webhook_url
        config["notify_slack"] = args.notify_slack or True
    if args.notify_slack:
        config["notify_slack"] = True
    if args.email_to:
        config.update({
            "notify_email": args.notify_email or True,
            "smtp_server": args.smtp_server,
            "smtp_port": args.smtp_port,
            "smtp_user": args.smtp_user,
            "smtp_pass": args.smtp_pass,
            "email_from": args.email_from,
            "email_to": args.email_to,
        })
    if args.telegram_bot_token:
        config.update({
            "notify_telegram": args.notify_telegram or True,
            "telegram_bot_token": args.telegram_bot_token,
            "telegram_chat_id": args.telegram_chat_id,
        })
    if args.quiet:
        config["verbose"] = False

    monitor = AuthLogMonitor(config)
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\n[+] Monitor stopped.")


if __name__ == "__main__":
    main()