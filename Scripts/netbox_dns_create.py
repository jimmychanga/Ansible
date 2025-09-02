import pynetbox
import os
import urllib3
import pydnsmgr
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=dotenv_path)

urllib3.disable_warnings()

NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
PRIMARY_DNS_SERVER = os.getenv("PRIMARY_DNS_SERVER")
USER = os.getenv("DNS_ADMIN")
PASS = os.getenv("DNS_PASSWORD")

try:
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN, threading=True)
    nb.http_session.verify = False  # Disable SSL verification (not recommended for production)
    # Query Netbox and revtriece all IPs with the DNS_NEEDED Tag
    tagged_ips = nb.ipam.ip_addresses.filter(tag_id=4)

    # Process IPs returned in the tagged_ips variable
    # Only IPs with the DNS_NEEDED tag will be returned
    for ip in tagged_ips:
        subnet = str(ip.address)
        ip_address = subnet.split('/')[0]  # Remove the / mask from the CIDR
        parts = ip.dns_name.split('.') # Split DNS name so we can remove the domain
        # Rejoin hostname bits
        hostname = ".".join(parts[:-2])  # Join all parts except the last two
        domain = ".".join(parts[-2:])  # Join the last two parts
        dns_session = pydnsmgr.DNSManager(PRIMARY_DNS_SERVER, USER, PASS)  # Create DNSManager instance
        status = dns_session.add_a_record(domain, hostname, ip_address)  # Save DNS record
        if status is not None:
            if status == 0:
                print(f"Successfully added DNS record: {ip.dns_name} -> {ip.address}")
            else:
                print(f"Failed to add DNS record: {ip.dns_name} -> {ip.address}")
        # Remove old tag and add new tag
        old_tag = nb.extras.tags.get(id=4)
        new_tag = nb.extras.tags.get(id=5)
        updated_tags = ip.tags
        for tag in updated_tags:
                updated_tags.remove(old_tag)    
        updated_tags.append({"id": 5})
        ip.update({"tags": updated_tags})  # Update tags
        status = ip.save()  # Save changes
        # Next step is to determine if IP is a primary for the device and then create CNAME record
        if ip.assigned_object and hasattr(ip.assigned_object, 'device'):
            device = ip.assigned_object.device
            if device.primary_ip and device.primary_ip.id == ip.id:
                cname_status = dns_session.add_cname_record(domain, device.name, ip.dns_name)
                if cname_status is not None:
                    if cname_status == 0:
                        print(f"Successfully added CNAME record: {device.name}.{domain} -> {ip.dns_name}")
                    else:
                        print(f"Failed to add CNAME record: {device.name}.{domain} -> {ip.dns_name}")

except Exception as e:
    print(f"Error connecting to NetBox: {e}")