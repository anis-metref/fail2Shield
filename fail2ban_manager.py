"""
Fail2ban Manager - Core class for interacting with fail2ban system
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import config
import utils

class Fail2banManager:
    """
    Manager class for interacting with fail2ban system
    """
    
    def __init__(self):
        self.client_path = config.FAIL2BAN_CLIENT_PATH
        self.timeout = config.COMMAND_TIMEOUT
    
    def is_fail2ban_running(self) -> bool:
        """
        Check if fail2ban service is running
        
        Returns:
            bool: True if running, False otherwise
        """
        success, stdout, stderr = utils.safe_execute_command([self.client_path, 'ping'])
        return success and 'pong' in stdout.lower()
    
    def get_jails_list(self) -> List[str]:
        """
        Get list of all configured jails
        
        Returns:
            List[str]: List of jail names
        """
        success, stdout, stderr = utils.safe_execute_command([self.client_path, 'status'])
        
        if not success:
            return []
        
        jails = []
        lines = stdout.split('\n')
        
        for line in lines:
            if 'Jail list:' in line:
                # Extract jail names from the line
                jail_part = line.split('Jail list:')[1].strip()
                if jail_part:
                    jails = [jail.strip() for jail in jail_part.split(',') if jail.strip()]
                break
        
        return jails
    
    def get_jail_status(self, jail_name: str) -> Dict:
        """
        Get detailed status of a specific jail
        
        Args:
            jail_name (str): Name of the jail
            
        Returns:
            Dict: Jail status information
        """
        success, stdout, stderr = utils.safe_execute_command([self.client_path, 'status', jail_name])
        
        if not success:
            return {
                'name': jail_name,
                'enabled': False,
                'error': stderr or 'Failed to get jail status'
            }
        
        status = {
            'name': jail_name,
            'enabled': True,
            'filter': '',
            'actions': [],
            'currently_failed': 0,
            'total_failed': 0,
            'currently_banned': 0,
            'total_banned': 0,
            'banned_ips': []
        }
        
        lines = stdout.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if 'Filter' in line and ':' in line:
                status['filter'] = line.split(':', 1)[1].strip()
            elif 'Actions' in line and ':' in line:
                actions_str = line.split(':', 1)[1].strip()
                status['actions'] = [action.strip() for action in actions_str.split(',') if action.strip()]
            elif 'Currently failed:' in line:
                try:
                    status['currently_failed'] = int(re.search(r'\d+', line).group())
                except:
                    pass
            elif 'Total failed:' in line:
                try:
                    status['total_failed'] = int(re.search(r'\d+', line).group())
                except:
                    pass
            elif 'Currently banned:' in line:
                try:
                    status['currently_banned'] = int(re.search(r'\d+', line).group())
                except:
                    pass
            elif 'Total banned:' in line:
                try:
                    status['total_banned'] = int(re.search(r'\d+', line).group())
                except:
                    pass
            elif 'Banned IP list:' in line:
                ips_str = line.split(':', 1)[1].strip()
                if ips_str:
                    status['banned_ips'] = [ip.strip() for ip in ips_str.split() if ip.strip()]
        
        return status
    
    def get_all_jails_status(self) -> List[Dict]:
        """
        Get status of all jails
        
        Returns:
            List[Dict]: List of jail status information
        """
        jails = self.get_jails_list()
        jails_status = []
        
        for jail in jails:
            status = self.get_jail_status(jail)
            jails_status.append(status)
        
        return jails_status
    
    def get_banned_ips(self, jail_name: str = None) -> Dict[str, List[str]]:
        """
        Get banned IPs for specific jail or all jails
        
        Args:
            jail_name (str, optional): Specific jail name
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping jail names to banned IP lists
        """
        banned_ips = {}
        
        if jail_name:
            jails = [jail_name]
        else:
            jails = self.get_jails_list()
        
        for jail in jails:
            status = self.get_jail_status(jail)
            if status.get('enabled', False):
                banned_ips[jail] = status.get('banned_ips', [])
        
        return banned_ips
    
    def ban_ip(self, jail_name: str, ip_address: str) -> Tuple[bool, str]:
        """
        Ban an IP address in a specific jail
        
        Args:
            jail_name (str): Name of the jail
            ip_address (str): IP address to ban
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        # Validate IP address
        if not utils.validate_ip_address(ip_address):
            return False, "Invalid IP address format"
        
        # Sanitize inputs
        jail_name = utils.sanitize_input(jail_name)
        ip_address = utils.sanitize_input(ip_address)
        
        success, stdout, stderr = utils.safe_execute_command([
            self.client_path, 'set', jail_name, 'banip', ip_address
        ])
        
        if success:
            return True, f"Successfully banned {ip_address} in jail {jail_name}"
        else:
            return False, stderr or f"Failed to ban {ip_address}"
    
    def ban_ip_with_time(self, jail_name: str, ip_address: str, ban_time: int) -> Tuple[bool, str]:
        """
        Ban an IP address in a specific jail with custom ban time
        
        Args:
            jail_name (str): Name of the jail
            ip_address (str): IP address to ban
            ban_time (int): Ban time in seconds (-1 for permanent)
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        # Validate IP address
        if not utils.validate_ip_address(ip_address):
            return False, "Invalid IP address format"
        
        # Sanitize inputs
        jail_name = utils.sanitize_input(jail_name)
        ip_address = utils.sanitize_input(ip_address)
        
        # For permanent ban, set a very long time or use banip directly
        if ban_time == -1:
            # Try to set bantime to -1 (permanent) then ban
            utils.safe_execute_command([
                self.client_path, 'set', jail_name, 'bantime', '-1'
            ])
            success, stdout, stderr = utils.safe_execute_command([
                self.client_path, 'set', jail_name, 'banip', ip_address
            ])
        else:
            # Set custom ban time then ban
            utils.safe_execute_command([
                self.client_path, 'set', jail_name, 'bantime', str(ban_time)
            ])
            success, stdout, stderr = utils.safe_execute_command([
                self.client_path, 'set', jail_name, 'banip', ip_address
            ])
        
        if success:
            ban_type = "permanently" if ban_time == -1 else f"for {ban_time} seconds"
            return True, f"Successfully banned {ip_address} {ban_type} in jail {jail_name}"
        else:
            return False, stderr or f"Failed to ban {ip_address}"
    
    def unban_ip(self, jail_name: str, ip_address: str) -> Tuple[bool, str]:
        """
        Unban an IP address from a specific jail
        
        Args:
            jail_name (str): Name of the jail
            ip_address (str): IP address to unban
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        # Validate IP address
        if not utils.validate_ip_address(ip_address):
            return False, "Invalid IP address format"
        
        # Sanitize inputs
        jail_name = utils.sanitize_input(jail_name)
        ip_address = utils.sanitize_input(ip_address)
        
        success, stdout, stderr = utils.safe_execute_command([
            self.client_path, 'set', jail_name, 'unbanip', ip_address
        ])
        
        if success:
            return True, f"Successfully unbanned {ip_address} from jail {jail_name}"
        else:
            return False, stderr or f"Failed to unban {ip_address}"
    
    def reload_jail(self, jail_name: str) -> Tuple[bool, str]:
        """
        Reload a specific jail
        
        Args:
            jail_name (str): Name of the jail to reload
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        jail_name = utils.sanitize_input(jail_name)
        
        success, stdout, stderr = utils.safe_execute_command([
            self.client_path, 'reload', jail_name
        ])
        
        if success:
            return True, f"Successfully reloaded jail {jail_name}"
        else:
            return False, stderr or f"Failed to reload jail {jail_name}"
    
    def start_jail(self, jail_name: str) -> Tuple[bool, str]:
        """
        Start a specific jail
        
        Args:
            jail_name (str): Name of the jail to start
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        jail_name = utils.sanitize_input(jail_name)
        
        success, stdout, stderr = utils.safe_execute_command([
            self.client_path, 'start', jail_name
        ])
        
        if success:
            return True, f"Successfully started jail {jail_name}"
        else:
            return False, stderr or f"Failed to start jail {jail_name}"
    
    def stop_jail(self, jail_name: str) -> Tuple[bool, str]:
        """
        Stop a specific jail
        
        Args:
            jail_name (str): Name of the jail to stop
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        jail_name = utils.sanitize_input(jail_name)
        
        success, stdout, stderr = utils.safe_execute_command([
            self.client_path, 'stop', jail_name
        ])
        
        if success:
            return True, f"Successfully stopped jail {jail_name}"
        else:
            return False, stderr or f"Failed to stop jail {jail_name}"
    
    def get_jail_config(self, jail_name: str) -> Dict:
        """
        Get configuration parameters for a specific jail
        
        Args:
            jail_name (str): Name of the jail
            
        Returns:
            Dict: Jail configuration parameters
        """
        config_params = {}
        
        # Common configuration parameters to query
        params = ['bantime', 'findtime', 'maxretry', 'logpath', 'backend']
        
        for param in params:
            success, stdout, stderr = utils.safe_execute_command([
                self.client_path, 'get', jail_name, param
            ])
            
            if success:
                config_params[param] = stdout.strip()
        
        return config_params
    
    def get_server_status(self) -> Dict:
        """
        Get overall fail2ban server status
        
        Returns:
            Dict: Server status information
        """
        status = {
            'running': self.is_fail2ban_running(),
            'version': '',
            'uptime': '',
            'total_jails': 0,
            'active_jails': 0
        }
        
        if status['running']:
            # Get version
            success, stdout, stderr = utils.safe_execute_command([self.client_path, 'version'])
            if success:
                status['version'] = stdout.strip()
            
            # Get jail statistics
            jails = self.get_all_jails_status()
            status['total_jails'] = len(jails)
            status['active_jails'] = len([j for j in jails if j.get('enabled', False)])
        
        return status