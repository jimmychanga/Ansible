import pynetbox
import os
import urllib3
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=dotenv_path)

urllib3.disable_warnings()

NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")

try:
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = False  # Disable SSL verification (not recommended for production)
    devices = nb.dcim.devices.all()

    print("NetBox Inventory:")
    for device in devices:
        print(f" - {device.name} (ID: {device.id})")
        device_name = device.name
        device.name = device_name.lower()
        device.save()
        print(f"Name changed to: "+ device_name.lower())
except Exception as e:
    print(f"Error connecting to NetBox: {e}")