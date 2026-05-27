import sys
import logging
import time
logging.basicConfig(level=logging.INFO)
sys.path.insert(0, '.')

from vidaa import VidaaTV

tv = VidaaTV(
    host="192.168.178.30",
    port=36669,
    use_dynamic_auth=True,
    mac_address="64:d8:1b:ec:18:10",
    enable_persistence=False,
)

print("Connecting...")
result = tv._try_static_connect(timeout=10)
print(f"Connected: {result}")

if result:
    print("\n>>> WATCH YOUR TV SCREEN NOW <<<")
    time.sleep(1)
    tv.start_pairing()
    print("Pairing request sent. PIN should appear on TV...")
    time.sleep(2)
    pin = input("Enter PIN from TV (leave blank if nothing appeared): ")
    if pin:
        if tv.authenticate(pin):
            print("SUCCESS! Authenticated!")
            print("Device info:", tv.get_device_info())
        else:
            print("Auth failed")
    else:
        print("No PIN seen - checking TV state...")
        print("State:", tv.get_state())

tv.disconnect()