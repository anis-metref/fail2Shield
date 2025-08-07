"""
Configuration file for Fail2Shield Dashboard
"""

import os

# Fail2ban configuration
FAIL2BAN_CLIENT_PATH = "/usr/bin/fail2ban-client"
FAIL2BAN_LOG_PATH = "/var/log/fail2ban.log"
FAIL2BAN_CONFIG_PATH = "/etc/fail2ban/"

# Application settings
APP_TITLE = "Fail2Shield Dashboard"
APP_PORT = 8501
AUTO_REFRESH_INTERVAL = 300  # seconds (5 minutes)
COMMAND_TIMEOUT = 10  # seconds

# API settings
IP_API_URL = "http://ip-api.com/json/"
IP_API_TIMEOUT = 5  # seconds

# UI Theme colors
COLORS = {
    'primary': '#1f77b4',
    'success': '#2ca02c',
    'warning': '#ff7f0e',
    'danger': '#d62728',
    'info': '#17a2b8',
    'light': '#f8f9fa',
    'dark': '#343a40',
    'gradient_start': '#667eea',
    'gradient_end': '#764ba2'
}

# Metrics configuration
METRICS_CONFIG = {
    'active_jails': {'color': COLORS['success']},
    'total_failures': {'color': COLORS['warning']},
    'total_banned': {'color': COLORS['danger']},
    'currently_banned': {'color': COLORS['info']}
}

# Default jails to monitor
DEFAULT_JAILS = [
    'sshd',
    'apache-auth',
    'apache-badbots',
    'apache-noscript',
    'apache-overflows',
    'nginx-http-auth',
    'nginx-limit-req',
    'postfix',
    'dovecot',
    'recidive'
]

# Log levels
LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']