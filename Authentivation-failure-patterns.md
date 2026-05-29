Service	Example
SSH	Failed password for root from 10.0.0.1
SSH (invalid user)	Failed password for invalid user admin from 10.0.0.1
SSH (pre-auth disconnect)	Did not receive identification string from 10.0.0.1
SSH (kex failure)	Unable to negotiate with 10.0.0.1
sudo	pam_unix(sudo:auth): authentication failure
su	pam_unix(su:auth): authentication failure
login	pam_unix(login:auth): authentication failure
Dropbear SSH	Bad password attempt for root from 10.0.0.1
dovecot	pam_unix(dovecot:auth): authentication failure
postfix SASL	sasl_username=admin authentication failed
vsftpd	pam_unix(vsftpd:auth): authentication failure
proftpd	USER root: Login incorrect
Generic PAM	pam_unix(sshd:auth): authentication failure

## Alerting Logic

Total threshold — when total failures across all sources exceeds --threshold within the time window, sends a summary alert
Per-IP threshold — when any single IP exceeds --threshold-per-ip, sends a targeted alert with the IP and geolocation (if enabled)
Watchlist — any failure involving a watchlist username immediately triggers an alert, even if below the numeric threshold
Each alert type is deduplicated within the time window to prevent notification spam.

## Example Alert Output (Console)
============================================================
[!] ALERT: Brute force from 185.220.101.34 — 12 attempts
============================================================
Target users: root(8), admin(3), ubuntu(1)
Channel	Setup Required
Console	None — always active
Discord	Webhook URL from Discord server settings
Slack	Webhook URL from Slack app configuration
Email	SMTP server (Gmail, SendGrid, or your own)
Telegram	Bot token from @BotFather + chat ID

## Dependencies
	pip install requests
## Example Scenarios
# Scenario 1: Monitoring during a pentest

python logmonitor.py \
    --threshold 20 \
    --window 600 \
    --exclude-ip 10.10.50.100 \
    --geo

Monitors for 20+ failures in 10 minutes, ignores your attacking machine, and shows attacker locations.

## Lisence
This tool is for authorized security testing only. The user is responsible for ensuring they have proper written authorization before deploying this tool against any system.
