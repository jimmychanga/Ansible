import pynetbox
import os
import urllib3

from dotenv import load_dotenv
from pathlib import Path

##########
# Load environment variables from .env file
##########
def load_env():
    dotenv_path = Path(__file__).parent / '.env'                                                                                                                                            
    load_dotenv(dotenv_path=dotenv_path)
    return {
        'NETBOX_URL': os.getenv("NETBOX_URL"),
        'NETBOX_TOKEN': os.getenv("NETBOX_TOKEN"),

    }

##########
# Get NetBox API client
##########
def get_netbox_api(url, token):
    nb = pynetbox.api(url, token=token, threading=True)
    nb.http_session.verify = False  # Disable SSL verification (not recommended for production)
    return nb

##########
# Main function
##########
def main():
    urllib3.disable_warnings()
    env = load_env()
    nb = get_netbox_api(env['NETBOX_URL'], env['NETBOX_TOKEN'])
    devices = nb.dcim.devices.filter(status='active', role=["backbone-router", "leaf-switch", "spine-switch"])

    oxidized_config_lines = []
    for device in devices:
        if device.primary_ip:
            # Assuming Oxidized uses the device name and primary IP for configuration
            # You might need to adjust this based on your Oxidized setup and device types
            oxidized_config_lines.append(f"{device.name}:{device.site.name.lower()}:{device.primary_ip.address.split('/')[0]}:{device.platform.slug}")
        else:
            print(f"Warning: Device {device.name} has no primary IP and will be skipped.")

    # Write to Oxidized router.db file (or similar)
    oxidized_router_db_path = '/home/jimmychanga/Ansible/Scripts/Netbox_oxidized/router.db'
    try:
        with open(oxidized_router_db_path, 'w') as f:
            for line in oxidized_config_lines:
                f.write(line + '\n')
        print(f"Successfully updated {oxidized_router_db_path}")
    except IOError as e:
        print(f"Error writing to Oxidized router.db: {e}")
    except Exception as e:
        print(f"Error connecting to NetBox: {e}")

if __name__ == "__main__":
    main()