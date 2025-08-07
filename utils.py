"""
Utility functions for Fail2Shield Dashboard
"""

import re
import ipaddress
import requests
import subprocess
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import config

def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6)
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Cache pour éviter les appels API répétés
_geolocation_cache = {}
_cache_timestamps = {}

def get_ip_geolocation(ip: str) -> Dict:
    """
    Get geolocation information for an IP address using ip-api.com
    
    Args:
        ip (str): IP address to lookup
        
    Returns:
        Dict: Geolocation information with fallback values
    """
    if not validate_ip_address(ip):
        return get_default_geo_info()
    
    # Check cache first with timestamp
    current_time = datetime.now()
    if ip in _geolocation_cache and ip in _cache_timestamps:
        cache_age = (current_time - _cache_timestamps[ip]).total_seconds()
        if cache_age < 3600:  # Cache valid for 1 hour
            return _geolocation_cache[ip]
    
    # Check if it's a private IP
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            geo_info = {
                'country': 'Réseau Local',
                'region': 'Réseau Privé',
                'city': 'LAN',
                'isp': 'Réseau Local',
                'org': 'Réseau Privé',
                'lat': 0,
                'lon': 0,
                'timezone': 'Local'
            }
            _geolocation_cache[ip] = geo_info
            _cache_timestamps[ip] = current_time
            return geo_info
    except:
        pass
    
    try:
        response = requests.get(
            f"{config.IP_API_URL}{ip}",
            timeout=config.IP_API_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                geo_info = {
                    'country': data.get('country') or 'Non déterminé',
                    'region': data.get('regionName') or 'Non déterminé',
                    'city': data.get('city') or 'Non déterminé',
                    'isp': data.get('isp') or 'Non déterminé',
                    'org': data.get('org') or 'Non déterminé',
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone') or 'Non déterminé'
                }
                _geolocation_cache[ip] = geo_info
                _cache_timestamps[ip] = current_time
                return geo_info
    except Exception as e:
        print(f"Error getting geolocation for {ip}: {e}")
    
    # Return default info if API fails
    geo_info = get_default_geo_info()
    _geolocation_cache[ip] = geo_info
    _cache_timestamps[ip] = current_time
    return geo_info

def get_default_geo_info() -> Dict:
    """
    Return default geolocation information when API fails
    
    Returns:
        Dict: Default geolocation information
    """
    return {
        'country': 'Non disponible',
        'region': 'Non disponible',
        'city': 'Non disponible',
        'isp': 'Non disponible',
        'org': 'Non disponible',
        'lat': 0,
        'lon': 0,
        'timezone': 'Non disponible'
    }

def parse_fail2ban_log(log_path: str, lines: int = 1000) -> List[Dict]:
    """
    Parse fail2ban log file and extract relevant information
    
    Args:
        log_path (str): Path to fail2ban log file
        lines (int): Number of lines to read from end of file
        
    Returns:
        List[Dict]: List of parsed log entries
    """
    entries = []
    
    try:
        # Read last N lines from log file
        result = subprocess.run(
            ['tail', '-n', str(lines), log_path],
            capture_output=True,
            text=True,
            timeout=config.COMMAND_TIMEOUT
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    entry = parse_log_line(line)
                    if entry:
                        entries.append(entry)
    except Exception as e:
        print(f"Error parsing log file: {e}")
    
    return entries

def parse_log_line(line: str) -> Optional[Dict]:
    """
    Parse a single log line and extract information
    
    Args:
        line (str): Log line to parse
        
    Returns:
        Optional[Dict]: Parsed log entry or None if parsing failed
    """
    # Pattern for fail2ban log entries
    patterns = {
        'ban': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*\[(\w+)\] BAN (\d+\.\d+\.\d+\.\d+)',
        'unban': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*\[(\w+)\] UNBAN (\d+\.\d+\.\d+\.\d+)',
        'found': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*\[(\w+)\] Found (\d+\.\d+\.\d+\.\d+)'
    }
    
    for action, pattern in patterns.items():
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'jail': match.group(2),
                'ip': match.group(3),
                'action': action,
                'raw_line': line
            }
    
    return None

def find_ssh_log_file() -> str:
    """
    Find the SSH authentication log file on the system
    
    Returns:
        str: Path to the SSH log file or empty string if not found
    """
    # Common SSH log file locations
    possible_paths = [
        "/var/log/auth.log",        # Ubuntu/Debian
        "/var/log/secure",          # CentOS/RHEL/Fedora
        "/var/log/messages",        # Some systems
        "/var/log/syslog",          # Alternative on some systems
        "/var/log/authlog",         # FreeBSD style
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.R_OK):
            # Check if file contains SSH entries
            try:
                result = subprocess.run(
                    ['tail', '-n', '100', path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and 'sshd' in result.stdout:
                    return path
            except:
                continue
    
    return ""

def parse_ssh_logs(log_path: str = None, lines: int = 1000) -> List[Dict]:
    """
    Parse SSH authentication logs to extract connection attempts
    
    Args:
        log_path (str): Path to auth log file (auto-detect if None)
        lines (int): Number of lines to read from end of file
        
    Returns:
        List[Dict]: List of SSH connection attempts
    """
    entries = []
    
    # Auto-detect log file if not specified
    if log_path is None:
        log_path = find_ssh_log_file()
    
    if not log_path:
        print("No SSH log file found or accessible")
        return entries
    
    try:
        # Check if file exists and is readable
        if not os.path.exists(log_path):
            print(f"SSH log file not found: {log_path}")
            return entries
        
        if not os.access(log_path, os.R_OK):
            print(f"SSH log file not readable: {log_path}")
            return entries
        
        # Read last N lines from auth log file
        result = subprocess.run(
            ['tail', '-n', str(lines), log_path],
            capture_output=True,
            text=True,
            timeout=config.COMMAND_TIMEOUT
        )
        
        if result.returncode == 0:
            ssh_lines = 0
            for line in result.stdout.split('\n'):
                if line.strip() and 'sshd' in line:
                    ssh_lines += 1
                    entry = parse_ssh_log_line(line)
                    if entry:
                        entries.append(entry)
            
            print(f"Processed {ssh_lines} SSH log lines from {log_path}")
        else:
            print(f"Error reading SSH log file: {result.stderr}")
            
    except Exception as e:
        print(f"Error parsing SSH log file: {e}")
    
    return entries

def parse_ssh_log_line(line: str) -> Optional[Dict]:
    """
    Parse a single SSH log line and extract connection information
    
    Args:
        line (str): SSH log line to parse
        
    Returns:
        Optional[Dict]: Parsed SSH entry or None if parsing failed
    """
    # Skip lines that don't contain sshd
    if 'sshd' not in line:
        return None
    
    # Patterns for SSH log entries - more comprehensive
    patterns = {
        'accepted': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Accepted \w+ for (\w+) from (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*Accepted \w+ for (\w+) from (\d+\.\d+\.\d+\.\d+)',
        ],
        'failed_password': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
        ],
        'failed': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed \w+ for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*Failed \w+ for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\w+)',
        ],
        'invalid_user': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)',
        ],
        'break_in': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*POSSIBLE BREAK-IN ATTEMPT.*from (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*POSSIBLE BREAK-IN ATTEMPT.*from (\d+\.\d+\.\d+\.\d+)',
        ],
        'disconnect': [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Disconnected from (?:invalid user )?(\w+) (\d+\.\d+\.\d+\.\d+)',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd.*Disconnected from (?:invalid user )?(\w+) (\d+\.\d+\.\d+\.\d+)',
        ]
    }
    
    for action, pattern_list in patterns.items():
        for pattern in pattern_list:
            match = re.search(pattern, line)
            if match:
                if action == 'break_in':
                    return {
                        'timestamp': match.group(1),
                        'user': 'unknown',
                        'ip': match.group(2),
                        'action': action,
                        'raw_line': line
                    }
                elif action == 'failed' and 'authentication failure' in line:
                    # Special case for authentication failure format
                    return {
                        'timestamp': match.group(1),
                        'user': match.group(3),
                        'ip': match.group(2),
                        'action': action,
                        'raw_line': line
                    }
                elif action == 'failed_password':
                    return {
                        'timestamp': match.group(1),
                        'user': match.group(2),
                        'ip': match.group(3),
                        'action': action,
                        'failure_type': 'Mot de passe incorrect',
                        'raw_line': line
                    }
                else:
                    return {
                        'timestamp': match.group(1),
                        'user': match.group(2),
                        'ip': match.group(3),
                        'action': action,
                        'raw_line': line
                    }
    
    return None

def get_ssh_connection_stats(ssh_entries: List[Dict]) -> Dict:
    """
    Analyze SSH connection entries and return statistics
    
    Args:
        ssh_entries (List[Dict]): List of SSH log entries
        
    Returns:
        Dict: SSH connection statistics
    """
    stats = {
        'accepted': {},
        'failed': {},
        'failed_password': {},
        'invalid_user': {},
        'break_in': {},
        'total_accepted': 0,
        'total_failed': 0,
        'total_failed_password': 0,
        'unique_ips': set(),
        'top_attacking_ips': {},
        'top_users_failed': {},
        'top_users_accepted': {},
        'failure_types': {}
    }
    
    for entry in ssh_entries:
        action = entry['action']
        ip = entry['ip']
        user = entry.get('user', 'unknown')
        
        stats['unique_ips'].add(ip)
        
        if action == 'accepted':
            stats['total_accepted'] += 1
            if ip not in stats['accepted']:
                stats['accepted'][ip] = []
            stats['accepted'][ip].append(user)
            
            # Count accepted users
            if user not in stats['top_users_accepted']:
                stats['top_users_accepted'][user] = 0
            stats['top_users_accepted'][user] += 1
            
        elif action == 'failed_password':
            stats['total_failed'] += 1
            stats['total_failed_password'] += 1
            
            if ip not in stats['failed_password']:
                stats['failed_password'][ip] = []
            stats['failed_password'][ip].append({
                'user': user,
                'failure_type': entry.get('failure_type', 'Mot de passe incorrect')
            })
            
            # Count attacking IPs
            if ip not in stats['top_attacking_ips']:
                stats['top_attacking_ips'][ip] = 0
            stats['top_attacking_ips'][ip] += 1
            
            # Count failed users
            if user not in stats['top_users_failed']:
                stats['top_users_failed'][user] = 0
            stats['top_users_failed'][user] += 1
            
            # Count failure types
            failure_type = entry.get('failure_type', 'Mot de passe incorrect')
            if failure_type not in stats['failure_types']:
                stats['failure_types'][failure_type] = 0
            stats['failure_types'][failure_type] += 1
            
        elif action in ['failed', 'invalid_user', 'break_in']:
            stats['total_failed'] += 1
            if ip not in stats['failed']:
                stats['failed'][ip] = []
            stats['failed'][ip].append({
                'user': user,
                'failure_type': 'Autre échec' if action == 'failed' else 
                              'Utilisateur invalide' if action == 'invalid_user' else 
                              'Tentative de piratage'
            })
            
            # Count attacking IPs
            if ip not in stats['top_attacking_ips']:
                stats['top_attacking_ips'][ip] = 0
            stats['top_attacking_ips'][ip] += 1
            
            # Count failed users
            if user not in stats['top_users_failed']:
                stats['top_users_failed'][user] = 0
            stats['top_users_failed'][user] += 1
            
            # Count failure types
            failure_type = 'Autre échec' if action == 'failed' else 'Utilisateur invalide' if action == 'invalid_user' else 'Tentative de piratage'
            if failure_type not in stats['failure_types']:
                stats['failure_types'][failure_type] = 0
            stats['failure_types'][failure_type] += 1
    
    # Convert sets to counts
    stats['unique_ips'] = len(stats['unique_ips'])
    
    return stats

def format_timestamp(timestamp: str) -> str:
    """
    Format timestamp for display
    
    Args:
        timestamp (str): Timestamp string
        
    Returns:
        str: Formatted timestamp
    """
    try:
        dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S,%f')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp

def get_system_info() -> Dict:
    """
    Get system information relevant to fail2ban
    
    Returns:
        Dict: System information
    """
    info = {}
    
    try:
        # Get fail2ban version
        result = subprocess.run(
            [config.FAIL2BAN_CLIENT_PATH, 'version'],
            capture_output=True,
            text=True,
            timeout=config.COMMAND_TIMEOUT
        )
        if result.returncode == 0:
            info['fail2ban_version'] = result.stdout.strip()
    except:
        info['fail2ban_version'] = 'Unknown'
    
    try:
        # Get system uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            uptime_days = int(uptime_seconds // 86400)
            uptime_hours = int((uptime_seconds % 86400) // 3600)
            info['uptime'] = f"{uptime_days}d {uptime_hours}h"
    except:
        info['uptime'] = 'Unknown'
    
    return info

def generate_report_data(jails_data: List[Dict], banned_ips: Dict) -> Dict:
    """
    Generate report data for dashboard
    
    Args:
        jails_data (List[Dict]): Jail information
        banned_ips (Dict): Banned IPs by jail
        
    Returns:
        Dict: Report data
    """
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total_jails': len(jails_data),
            'active_jails': len([j for j in jails_data if j.get('enabled', False)]),
            'total_banned_ips': sum(len(ips) for ips in banned_ips.values()),
            'total_failures': sum(j.get('failed', 0) for j in jails_data)
        },
        'jails': jails_data,
        'banned_ips': banned_ips
    }
    
    return report

def safe_execute_command(command: List[str], timeout: int = None) -> Tuple[bool, str, str]:
    """
    Safely execute a system command with timeout
    
    Args:
        command (List[str]): Command to execute
        timeout (int): Timeout in seconds
        
    Returns:
        Tuple[bool, str, str]: (success, stdout, stderr)
    """
    if timeout is None:
        timeout = config.COMMAND_TIMEOUT
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input to prevent command injection
    
    Args:
        input_str (str): Input string to sanitize
        
    Returns:
        str: Sanitized string
    """
    # Remove potentially dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\']
    sanitized = input_str
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()