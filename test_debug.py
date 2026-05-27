import sys
import logging
import time
logging.basicConfig(level=logging.INFO)
sys.path.insert(0, '.')

from vidaa import VidaaTV
import vidaa.topics as topics

tv = VidaaTV(
    host="192.168.178.30",
    port=36669,
    use_dynamic_auth=True,
    mac_address="64:d8:1b:ec:18:10",
    enable_persistence=False,
)

print("Connecting with static credentials...")
result = tv._try_static_connect(timeout=10)
print(f"Connected: {result}")

if not result:
    print("Connection failed")
    sys.exit(1)

# Show exactly what topic start_pairing() will use
print(f"\nClient ID for topics: '{tv.client_id}'")
print(f"VIDAA_CONNECT topic: {topics.get_topic(topics.TOPIC_VIDAA_CONNECT, tv.client_id)}")
print(f"AUTH_RESPONSE topic: {topics.get_topic(topics.TOPIC_AUTH_RESPONSE, tv.client_id)}")

# Check TV state before pairing
print("\nChecking TV state before pairing...")
state = tv.get_state(timeout=3)
print(f"TV state: {state}")

# Send pairing request
print("\n>>> WATCH TV SCREEN NOW - sending pairing request <<<")
time.sleep(1)
ok = tv.start_pairing()
print(f"start_pairing() returned: {ok}")

# Wait and check state again
print("Waiting 5 seconds...")
time.sleep(5)
state2 = tv.get_state(timeout=3)
print(f"TV state after pairing request: {state2}")
print(f"needs_authentication: {tv.needs_authentication()}")
print(f"is_authenticated: {tv.is_authenticated()}")

pin = input("\nEnter PIN if you saw one (or press Enter to skip): ")
if pin:
    result = tv.authenticate(pin)
    print(f"Auth result: {result}")

tv.disconnect()
