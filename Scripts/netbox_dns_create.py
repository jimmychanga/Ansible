import pynetbox
import os
import urllib3
import pydnsmgr
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
        'PRIMARY_DNS_SERVER': os.getenv("PRIMARY_DNS_SERVER"),
        'USER': os.getenv("DNS_ADMIN"),
        'PASS': os.getenv("DNS_PASSWORD")
    }

##########
# Get NetBox API client
##########
def get_netbox_api(url, token):
    nb = pynetbox.api(url, token=token, threading=True)
    nb.http_session.verify = False  # Disable SSL verification (not recommended for production)
    return nb

##########
# Process IP address
##########
def process_ip(ip, dns_session, nb):
    subnet = str(ip.address)
    ip_address = subnet.split('/')[0]
    parts = ip.dns_name.split('.')
    hostname = ".".join(parts[:-2])
    domain = ".".join(parts[-2:])

    status = dns_session.add_a_record(domain, hostname, ip_address)
    if status is not None:
        if status == 0:
            print(f"Successfully added DNS record: {ip.dns_name} -> {ip.address}")
        else:
            print(f"Failed to add DNS record: {ip.dns_name} -> {ip.address}")

    update_tags(ip, nb)
    create_cname_if_primary(ip, dns_session, domain)

##########
# Update IP tags
##########
def update_tags(ip, nb):
    # Remove tag with ID 4 and add tag with ID 5
    updated_tags = [tag for tag in ip.tags if isinstance(tag, dict) and tag.get('id') != 4]
    updated_tags.append({"id": 5})
    ip.update({"tags": updated_tags})
    ip.save()

##########
# Create CNAME record if IP is primary for a device
##########
def create_cname_if_primary(ip, dns_session, domain):
     if ip.assigned_object and hasattr(ip.assigned_object, 'device'):
        device = ip.assigned_object.device
        if hasattr(device, 'primary_ip') and device.primary_ip and device.primary_ip.id == ip.id:
            cname_status = dns_session.add_cname_record(domain, device.name, ip.dns_name)
            if cname_status is not None:
                if cname_status == 0:
                    print(f"Successfully added CNAME record: {device.name}.{domain} -> {ip.dns_name}")
                else:
                    print(f"Failed to add CNAME record: {device.name}.{domain} -> {ip.dns_name}")

##########
# Main function
##########
def main():
    urllib3.disable_warnings()
    env = load_env()
    try:
        nb = get_netbox_api(env['NETBOX_URL'], env['NETBOX_TOKEN'])
        tagged_ips = nb.ipam.ip_addresses.filter(tag_id=4)
        dns_session = pydnsmgr.DNSManager(env['PRIMARY_DNS_SERVER'], env['USER'], env['PASS'])
        for ip in tagged_ips:
            process_ip(ip, dns_session, nb)
    except Exception as e:
        print(f"Error connecting to NetBox: {e}")

if __name__ == "__main__":
    main()