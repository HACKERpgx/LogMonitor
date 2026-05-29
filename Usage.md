Configuration File
You can provide all settings in a JSON file:


{
    "threshold": 10,
    "time_window": 120,
    "threshold_per_ip": 3,
    "geo_lookup": true,
    "notify_discord": true,
    "discord_webhook_url": "https://discord.com/api/webhooks/...",
    "notify_telegram": true,
    "telegram_bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
    "telegram_chat_id": "987654321",
    "exclude_ips": ["192.168.1.100", "10.0.0.5"],
    "watchlist_usernames": ["root", "admin", "administrator", "sa"]
}

python logmonitor.py --config config.json
