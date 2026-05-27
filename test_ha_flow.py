import sys
import logging
logging.basicConfig(level=logging.INFO)
sys.path.insert(0, '.')

from vidaa import VidaaTV

tv = VidaaTV(
    host="192.168.178.30",
    port=36669,
    use_dynamic_auth=True,
    mac_address="64:d8:1b:ec:18:10",
)

print("Connecting with dynamic auth + fallback...")
if not tv.connect(timeout=15):
    print("FAILED - fix not working")
    sys.exit(1)

print("Connected! Starting pairing...")
tv.start_pairing()
pin = input("Enter PIN from TV: ")

if tv.authenticate(pin):
    print("SUCCESS - full flow works!")
    print("Device info:", tv.get_device_info())
else:
    print("Auth failed")

tv.disconnect()