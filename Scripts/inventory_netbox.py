import pynetbox
import os

NETBOX_URL = os.getenv('NETBOX_URL', 'https://foxtail.bodiddely.internal')
NETBOX_TOKEN = os.getenv('NETBOX_TOKEN', 'a9748a500da7bf7acf04ac0499b9f7da1d9f5dc3')

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