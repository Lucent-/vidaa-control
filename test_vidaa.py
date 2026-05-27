# test_vidaa.py
import sys
sys.path.insert(0, '.')  # run from vidaa-control root

from vidaa import VidaaTV

tv = VidaaTV(
    host="192.168.178.30",
    port=36669,
    use_dynamic_auth=False,      # force static credentials
    auto_detect_protocol=False,  # skip failing HTTP detection
)

print("Connecting...")
if not tv.connect(timeout=10):
    print("Connection failed")
    sys.exit(1)

print("Connected! Starting pairing...")
if not tv.start_pairing():
    print("Failed to start pairing")
    sys.exit(1)

print("Check your TV screen for a PIN...")
pin = input("Enter PIN from TV: ")

if tv.authenticate(pin):
    print("Authenticated successfully!")
    info = tv.get_device_info()
    print("Device info:", info)
else:
    print("Authentication failed")

tv.disconnect()