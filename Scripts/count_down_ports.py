#!/usr/bin/env python3
"""
Network Port Status Checker
Connects to network switches (Cisco, Arista, Juniper) and counts down ports.
Auto-detects device manufacturer and supports single device or bulk device list.
"""

import argparse
import sys
import getpass
from typing import Dict, List, Tuple, Optional
from netmiko import ConnectHandler, SSHDetect
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
import concurrent.futures


class PortChecker:
    """Check port status on network devices"""
    
    def __init__(self, username: str, password: str, enable_secret: Optional[str] = None):
        self.username = username
        self.password = password
        self.enable_secret = enable_secret or password
        
    def auto_detect_device(self, host: str) -> Optional[str]:
        """
        Auto-detect device type using Netmiko's SSHDetect
        
        Args:
            host: IP address or hostname
            
        Returns:
            Device type string or None if detection fails
        """
        device = {
            'device_type': 'autodetect',
            'host': host,
            'username': self.username,
            'password': self.password,
            'secret': self.enable_secret,
        }
        
        try:
            guesser = SSHDetect(**device)
            best_match = guesser.autodetect()
            guesser.connection.disconnect()
            return best_match
        except Exception as e:
            print(f"  Error detecting device type for {host}: {e}")
            return None
    
    def count_down_ports_cisco_ios(self, connection) -> Tuple[int, int, List[str]]:
        """
        Count down ports on Cisco IOS devices
        
        Returns:
            Tuple of (total_ports, down_ports, list_of_down_ports)
        """
        output = connection.send_command("show interfaces status")
        lines = output.split('\n')
        
        total_ports = 0
        down_ports = 0
        down_port_list = []
        
        for line in lines:
            # Skip header lines
            if 'Port' in line or 'Name' in line or '----' in line or not line.strip():
                continue
            
            # Parse interface status
            parts = line.split()
            if len(parts) >= 2:
                interface = parts[0]
                # Look for status indicators
                if 'notconnect' in line.lower() or 'disabled' in line.lower() or 'err-disabled' in line.lower():
                    down_ports += 1
                    down_port_list.append(interface)
                    total_ports += 1
                elif 'connected' in line.lower():
                    total_ports += 1
        
        return total_ports, down_ports, down_port_list
    
    def count_down_ports_cisco_nxos(self, connection) -> Tuple[int, int, List[str]]:
        """
        Count down ports on Cisco NXOS devices
        
        Returns:
            Tuple of (total_ports, down_ports, list_of_down_ports)
        """
        output = connection.send_command("show interface status")
        lines = output.split('\n')
        
        total_ports = 0
        down_ports = 0
        down_port_list = []
        
        for line in lines:
            # Skip header lines and separators
            if 'Port' in line or 'Name' in line or '----' in line or not line.strip():
                continue
            
            # Parse interface status - NXOS format is similar but may have slight differences
            parts = line.split()
            if len(parts) >= 2:
                interface = parts[0]
                # NXOS status indicators
                if 'notconnect' in line.lower() or 'disabled' in line.lower() or 'err-disabled' in line.lower() or 'sfpabsent' in line.lower():
                    down_ports += 1
                    down_port_list.append(interface)
                    total_ports += 1
                elif 'connected' in line.lower():
                    total_ports += 1
        
        return total_ports, down_ports, down_port_list
    
    def count_down_ports_arista(self, connection) -> Tuple[int, int, List[str]]:
        """
        Count down ports on Arista devices
        
        Returns:
            Tuple of (total_ports, down_ports, list_of_down_ports)
        """
        output = connection.send_command("show interfaces status")
        lines = output.split('\n')
        
        total_ports = 0
        down_ports = 0
        down_port_list = []
        
        for line in lines:
            # Skip header lines
            if 'Port' in line or 'Name' in line or '----' in line or not line.strip():
                continue
            
            # Parse interface status
            parts = line.split()
            if len(parts) >= 2:
                interface = parts[0]
                # Check for down status
                if 'notconnect' in line.lower() or 'disabled' in line.lower() or 'errdisabled' in line.lower():
                    down_ports += 1
                    down_port_list.append(interface)
                    total_ports += 1
                elif 'connected' in line.lower():
                    total_ports += 1
        
        return total_ports, down_ports, down_port_list
    
    def count_down_ports_juniper(self, connection) -> Tuple[int, int, List[str]]:
        """
        Count down ports on Juniper devices
        
        Returns:
            Tuple of (total_ports, down_ports, list_of_down_ports)
        """
        output = connection.send_command("show interfaces terse | match \"up|down\"")
        lines = output.split('\n')
        
        total_ports = 0
        down_ports = 0
        down_port_list = []
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                interface = parts[0]
                # Only count physical interfaces (ge-, xe-, et-, etc.)
                if any(interface.startswith(prefix) for prefix in ['ge-', 'xe-', 'et-', 'fe-']):
                    total_ports += 1
                    # Check link and admin status
                    if 'down' in line.lower():
                        down_ports += 1
                        down_port_list.append(interface)
        
        return total_ports, down_ports, down_port_list
    
    def check_device(self, host: str, device_type: Optional[str] = None) -> Dict:
        """
        Connect to a device and count down ports
        
        Args:
            host: IP address or hostname
            device_type: Optional device type (will auto-detect if not provided)
            
        Returns:
            Dictionary with results
        """
        result = {
            'host': host,
            'success': False,
            'device_type': None,
            'total_ports': 0,
            'down_ports': 0,
            'down_port_list': [],
            'error': None
        }
        
        try:
            # Auto-detect device type if not provided
            if not device_type:
                print(f"Detecting device type for {host}...")
                device_type = self.auto_detect_device(host)
                if not device_type:
                    result['error'] = "Could not detect device type"
                    return result
            
            result['device_type'] = device_type
            print(f"Connecting to {host} ({device_type})...")
            
            # Connect to device
            device = {
                'device_type': device_type,
                'host': host,
                'username': self.username,
                'password': self.password,
                'secret': self.enable_secret,
            }
            
            connection = ConnectHandler(**device)
            
            # Count ports based on device type
            if 'cisco_ios' in device_type.lower():
                total, down, down_list = self.count_down_ports_cisco_ios(connection)
            elif 'cisco_nxos' in device_type.lower():
                total, down, down_list = self.count_down_ports_cisco_nxos(connection)
            elif 'cisco' in device_type.lower():  # Fallback for generic cisco detection
                total, down, down_list = self.count_down_ports_cisco_ios(connection)
            elif 'arista' in device_type.lower():
                total, down, down_list = self.count_down_ports_arista(connection)
            elif 'juniper' in device_type.lower():
                total, down, down_list = self.count_down_ports_juniper(connection)
            else:
                result['error'] = f"Unsupported device type: {device_type}"
                connection.disconnect()
                return result
            
            result['total_ports'] = total
            result['down_ports'] = down
            result['down_port_list'] = down_list
            result['success'] = True
            
            connection.disconnect()
            
        except NetmikoAuthenticationException:
            result['error'] = "Authentication failed"
        except NetmikoTimeoutException:
            result['error'] = "Connection timeout"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_devices(self, hosts: List[str], parallel: bool = False) -> List[Dict]:
        """
        Check multiple devices
        
        Args:
            hosts: List of IP addresses or hostnames
            parallel: Whether to check devices in parallel
            
        Returns:
            List of result dictionaries
        """
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(self.check_device, hosts))
        else:
            results = [self.check_device(host) for host in hosts]
        
        return results


def read_device_list(filename: str) -> List[str]:
    """
    Read device list from file
    
    Args:
        filename: Path to file containing device list (one per line)
        
    Returns:
        List of device hostnames/IPs
    """
    devices = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    devices.append(line)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    return devices


def print_results(results: List[Dict], verbose: bool = False):
    """
    Print results in a formatted table
    
    Args:
        results: List of result dictionaries
        verbose: Whether to show detailed port lists
    """
    print("\n" + "="*80)
    print(f"{'Device':<30} {'Type':<20} {'Total':<8} {'Down':<8} {'Status'}")
    print("="*80)
    
    total_devices = len(results)
    successful = 0
    total_ports_all = 0
    total_down_all = 0
    
    for result in results:
        if result['success']:
            successful += 1
            total_ports_all += result['total_ports']
            total_down_all += result['down_ports']
            
            device_type = result['device_type'].replace('_ssh', '').replace('cisco_', '').replace('arista_', '').replace('juniper_', '')
            print(f"{result['host']:<30} {device_type:<20} {result['total_ports']:<8} {result['down_ports']:<8} OK")
            
            if verbose and result['down_port_list']:
                print(f"  Down ports: {', '.join(result['down_port_list'])}")
        else:
            print(f"{result['host']:<30} {'N/A':<20} {'N/A':<8} {'N/A':<8} FAILED: {result['error']}")
    
    print("="*80)
    print(f"Summary: {successful}/{total_devices} devices checked successfully")
    print(f"Total ports across all devices: {total_ports_all}")
    print(f"Total down ports across all devices: {total_down_all}")
    if total_ports_all > 0:
        percentage = (total_down_all / total_ports_all) * 100
        print(f"Percentage of down ports: {percentage:.2f}%")
    print("="*80)


def main():
    parser = argparse.ArgumentParser(
        description='Check port status on network switches (Cisco, Arista, Juniper)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d 192.168.1.1 -u admin
  %(prog)s -f devices.txt -u admin -p
  %(prog)s -d switch1.example.com -u admin -v
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--device', help='Single device IP or hostname')
    group.add_argument('-f', '--file', help='File containing list of devices (one per line)')
    
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-w', '--password', help='SSH password (will prompt if not provided)')
    parser.add_argument('-e', '--enable', help='Enable/privileged password (defaults to SSH password)')
    parser.add_argument('-p', '--parallel', action='store_true', help='Check devices in parallel')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed port lists')
    
    args = parser.parse_args()
    
    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass("Enter SSH password: ")
    
    # Get enable password
    enable_secret = args.enable
    if not enable_secret:
        enable_secret = password
    
    # Create checker instance
    checker = PortChecker(args.username, password, enable_secret)
    
    # Get device list
    if args.device:
        devices = [args.device]
    else:
        devices = read_device_list(args.file)
        print(f"Loaded {len(devices)} devices from {args.file}")
    
    # Check devices
    print(f"\nChecking {len(devices)} device(s)...\n")
    results = checker.check_devices(devices, parallel=args.parallel)
    
    # Print results
    print_results(results, verbose=args.verbose)


if __name__ == '__main__':
    main()
