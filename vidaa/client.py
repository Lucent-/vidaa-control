"""Vidaa TV MQTT client.

Provides control of Hisense/Vidaa TVs via MQTT over SSL/TLS.
Supports authentication, remote control, volume, sources, and apps.
"""

import hashlib
import json
import logging
import os
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)

# paho-mqtt v2 compat: use VERSION1 callback API if available
_MQTT_CLIENT_KWARGS: dict = {}
if hasattr(mqtt, "CallbackAPIVersion"):
    _MQTT_CLIENT_KWARGS["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION1

from .config import (
    DEFAULT_PORT,
    DEFAULT_MQTT_USERNAME,
    DEFAULT_MQTT_PASSWORD,
    DEFAULT_CLIENT_ID,
    DEFAULT_CERT_FILENAME,
    DEFAULT_KEY_FILENAME,
    TokenStorage,
    get_storage,
)
from .credentials import generate_credentials, generate_credentials_static
from .keys import ALL_KEYS
from .protocol import AuthMethod, detect_protocol, get_auth_method, get_auth_method_order
from .topics import (
    APPS,
    CLIENT_ID,
    SOURCE_MAP,
    TOPIC_AUTH,
    TOPIC_AUTH_CLOSE,
    TOPIC_GET_TOKEN,
    TOPIC_VIDAA_CONNECT,
    TOPIC_GET_APPS,
    TOPIC_GET_SOURCES,
    TOPIC_GET_STATE,
    TOPIC_GET_VOLUME,
    TOPIC_GET_TV_INFO,
    TOPIC_GET_DEVICE_INFO,
    TOPIC_GET_CAPABILITY,
    TOPIC_LAUNCH_APP,
    TOPIC_SEND_KEY,
    TOPIC_SET_SOURCE,
    TOPIC_SET_VOLUME,
    TOPIC_APPS_RESPONSE,
    TOPIC_SOURCES_RESPONSE,
    TOPIC_STATE_RESPONSE,
    TOPIC_VOLUME_RESPONSE,
    TOPIC_AUTH_RESPONSE,
    TOPIC_AUTH_CODE_RESPONSE,
    TOPIC_TOKEN_RESPONSE,
    TOPIC_TV_INFO_RESPONSE,
    TOPIC_DEVICE_INFO_RESPONSE,
    TOPIC_CAPABILITY_RESPONSE,
    get_topic,
)


class VidaaTV:
    """Client to control Hisense TV via MQTT."""

    # Default certificate paths (relative to package or absolute)
    _CERTS_DIR = Path(__file__).parent / "certs"

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        username: str = DEFAULT_MQTT_USERNAME,
        password: str = DEFAULT_MQTT_PASSWORD,
        client_id: str = DEFAULT_CLIENT_ID,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        enable_persistence: bool = True,
        storage: Optional[TokenStorage] = None,
        on_state_change: Optional[Callable[[dict], None]] = None,
        on_auth_required: Optional[Callable[[], None]] = None,
        mac_address: Optional[str] = None,
        use_dynamic_auth: bool = False,
        brand: str = "his",
        auth_method: Optional[AuthMethod] = None,
        auto_detect_protocol: bool = True,
    ):
        """Initialize the Vidaa TV client.

        Args:
            host: TV IP address
            port: MQTT port (default 36669)
            username: MQTT username (default 'hisenseservice')
            password: MQTT password (default 'multimqttservice')
            client_id: Client identifier for MQTT topics
            use_ssl: Enable SSL/TLS connection
            verify_ssl: Verify SSL certificate (set False for self-signed)
            certfile: Path to client certificate file (PEM format)
            keyfile: Path to client private key file (PKCS8 format)
            enable_persistence: Save/load auth tokens for automatic reconnection
            storage: Custom TokenStorage instance (uses default if None)
            on_state_change: Callback for state updates
            on_auth_required: Callback when TV requires PIN authentication
            mac_address: Device MAC address (required for dynamic auth)
            use_dynamic_auth: Use dynamic credential generation algorithm
            brand: TV brand identifier (default 'his' for Hisense)
            auth_method: Authentication method (LEGACY, MIDDLE, MODERN).
                        If None and auto_detect_protocol is True, will auto-detect.
            auto_detect_protocol: Automatically detect protocol version from TV.
                                 Only used when auth_method is None.
        """
        self.host = host
        self.port = port
        self.client_id = client_id
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.enable_persistence = enable_persistence
        self.on_state_change = on_state_change
        self.on_auth_required = on_auth_required
        self.mac_address = mac_address
        self.use_dynamic_auth = use_dynamic_auth
        self.brand = brand

        # Protocol detection and auth method
        self._auth_method = auth_method
        self._protocol_version: Optional[int] = None
        self._auto_detect_protocol = auto_detect_protocol

        # Token storage (initialised early so protocol cache check can use it)
        self._storage = storage or (get_storage() if enable_persistence else None)

        # Auto-detect protocol if needed and dynamic auth is enabled
        if use_dynamic_auth and auth_method is None and auto_detect_protocol:
            # Check storage for a cached protocol version first (avoids HTTP request)
            cached_pv = self._storage.get_cached_protocol_version(
                device_id=mac_address, host=host, port=port,
            ) if self._storage else None

            if cached_pv is not None:
                self._protocol_version = cached_pv
                self._auth_method = get_auth_method(cached_pv)
                _LOGGER.debug("Using cached protocol version: %s -> %s", cached_pv, self._auth_method.value)
            else:
                self._protocol_version = detect_protocol(host)
                self._auth_method = get_auth_method(self._protocol_version)
                if self._protocol_version is not None:
                    _LOGGER.info("Detected protocol version: %s -> %s", self._protocol_version, self._auth_method.value)
                else:
                    _LOGGER.warning("Could not detect protocol. Using %s auth (will try fallback if fails)", self._auth_method.value)

        self._access_token: Optional[str] = None
        self._authenticated = False
        self._auth_required = False

        self._connected = False
        self._response_event = threading.Event()
        self._auth_event = threading.Event()
        self._last_response: Optional[dict] = None
        self._state: dict = {}
        self._cached_volume: Optional[int] = None
        self._cached_muted: bool = False

        # Track if we need to refresh token after connecting
        self._pending_token_refresh = False
        self._refresh_token: Optional[str] = None

        # Check for saved credentials first (after successful pairing)
        saved_creds = self._load_saved_credentials()
        if saved_creds:
            if saved_creds.get("needs_reauth"):
                _LOGGER.info("Stored tokens expired. Need to re-authenticate.")
                if use_dynamic_auth and mac_address:
                    saved_creds = None
                else:
                    _LOGGER.warning("Cannot generate fresh credentials without mac_address")

            elif saved_creds.get("needs_refresh"):
                self._mqtt_client_id = saved_creds["client_id"]
                self._username = saved_creds["mqtt_username"]
                self._password = saved_creds["refresh_token"]
                self._refresh_token = saved_creds["refresh_token"]
                self._pending_token_refresh = True
                self.client_id = saved_creds["client_id"]
                if saved_creds.get("auth_method"):
                    self._auth_method = AuthMethod(saved_creds["auth_method"])
                if saved_creds.get("protocol_version"):
                    self._protocol_version = saved_creds["protocol_version"]
                hours_left = saved_creds.get("refresh_expires_in", 0) // 3600
                _LOGGER.info("Access token expired. Will refresh (refresh token valid for %dh)...", hours_left)

            elif saved_creds.get("access_token"):
                self._mqtt_client_id = saved_creds["client_id"]
                self._username = saved_creds["mqtt_username"]
                self._password = saved_creds["access_token"]
                self._access_token = saved_creds["access_token"]
                self._refresh_token = saved_creds.get("refresh_token")
                self._authenticated = True
                self.client_id = saved_creds["client_id"]
                if saved_creds.get("auth_method"):
                    self._auth_method = AuthMethod(saved_creds["auth_method"])
                if saved_creds.get("protocol_version"):
                    self._protocol_version = saved_creds["protocol_version"]
                hours_left = saved_creds.get("access_expires_in", 0) // 3600
                _LOGGER.debug("Using saved credentials (valid for %dh): client_id=%s...", hours_left, self._mqtt_client_id[:30])

        if not saved_creds:
            if use_dynamic_auth and mac_address:
                creds = generate_credentials(
                    mac_address=mac_address,
                    brand=brand,
                    auth_method=self._auth_method,
                )
                self._mqtt_client_id = creds.client_id
                self._username = creds.username
                self._password = creds.password
                self.client_id = creds.client_id
                auth_label = self._auth_method.value if self._auth_method else "auto"
                _LOGGER.debug("Using dynamic auth (%s): client_id=%s...", auth_label, creds.client_id[:30])
            else:
                self._mqtt_client_id = f"hisense_{client_id}_{int(time.time())}"
                self._username = username
                self._password = password

        # Create MQTT client
        self._client = mqtt.Client(
            client_id=self._mqtt_client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
            transport="tcp",
            **_MQTT_CLIENT_KWARGS,
        )
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

        # Configure SSL
        if use_ssl:
            cert = certfile or (self._CERTS_DIR / DEFAULT_CERT_FILENAME)
            key = keyfile or (self._CERTS_DIR / DEFAULT_KEY_FILENAME)

            if os.path.exists(cert) and os.path.exists(key):
                self._client.username_pw_set(self._username, self._password)
                self._client.tls_set(
                    ca_certs=None,
                    certfile=str(cert),
                    keyfile=str(key),
                    cert_reqs=ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLS,
                )
                self._client.tls_insecure_set(True)
            else:
                self._client.username_pw_set(self._username, self._password)
                context = ssl.create_default_context()
                if not verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self._client.tls_set_context(context)
        else:
            self._client.username_pw_set(self._username, self._password)

    def _load_saved_credentials(self) -> Optional[dict]:
        """Load saved credentials from storage for reconnection."""
        if not self._storage:
            return None

        token_data = self._storage.get_token(
            device_id=self.mac_address,
            host=self.host,
            port=self.port,
        )
        if not token_data:
            return None

        client_id = token_data.get("client_id")
        mqtt_username = token_data.get("mqtt_username")
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if not (client_id and mqtt_username):
            return None

        status = self._storage.get_token_status(
            device_id=self.mac_address,
            host=self.host,
            port=self.port,
        )

        return {
            "client_id": client_id,
            "mqtt_username": mqtt_username,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "uuid": token_data.get("uuid"),
            "needs_refresh": status.get("needs_refresh", False),
            "needs_reauth": status.get("needs_reauth", False),
            "access_expires_in": status.get("access_expires_in", 0),
            "refresh_expires_in": status.get("refresh_expires_in", 0),
            "auth_method": token_data.get("auth_method"),
            "protocol_version": token_data.get("protocol_version"),
        }

    def _load_saved_token(self) -> bool:
        """Load saved token from storage."""
        if not self._storage:
            return False

        token_data = self._storage.get_token(self.host, self.port)
        if token_data and not token_data.get("needs_refresh"):
            self._access_token = token_data.get("access_token")
            self._authenticated = True
            return True

        return False

    def connect(self, timeout: float = 10.0, auto_auth: bool = True, auto_refresh: bool = True, try_fallback: bool = True) -> bool:
        """Connect to the TV."""
        # Proactively try static credentials first before any dynamic attempts.
        # Some VIDAA licensed TVs (e.g. Toshiba) reject dynamic auth but accept
        # hisenseservice/multimqttservice. Trying static first avoids triggering
        # rate limiting from failed dynamic attempts.
        if self.use_dynamic_auth and self.mac_address and try_fallback:
            _LOGGER.info("Trying static credentials before dynamic auth...")
            if self._try_static_connect(timeout=min(timeout, 8.0)):
                return True
            _LOGGER.info("Static credentials failed, proceeding with dynamic auth...")

        try:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass
            self._connected = False

            self._client.connect(self.host, self.port, keepalive=60)
            self._client.loop_start()

            start = time.time()
            while not self._connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if not self._connected:
                self._client.loop_stop()
                if try_fallback and self.use_dynamic_auth and self.mac_address:
                    return self._connect_with_fallback(timeout=timeout, auto_refresh=auto_refresh)
                return False

            if auto_refresh and self._pending_token_refresh:
                if not self.refresh_token(timeout=timeout):
                    _LOGGER.warning("Token refresh failed, connection may not work")

            return self._connected
        except Exception as e:
            _LOGGER.debug("Connection failed: %s", e)
            try:
                self._client.loop_stop()
            except Exception:
                pass
            if try_fallback and self.use_dynamic_auth and self.mac_address:
                return self._connect_with_fallback(timeout=timeout, auto_refresh=auto_refresh)
            return False

    def _try_static_connect(self, timeout: float = 10.0) -> bool:
        """Try connecting with static default credentials.

        Uses proper callbacks so _on_connect fires and all topic
        subscriptions are set up correctly on successful connection.
        Restores previous state if connection fails.
        """
        static_client_id = f"hisense_{DEFAULT_CLIENT_ID}_{int(time.time())}"

        # Save current state so we can restore on failure
        old_client = self._client
        old_mqtt_client_id = self._mqtt_client_id
        old_username = self._username
        old_password = self._password
        old_client_id = self.client_id
        old_auth_method = self._auth_method

        # Switch to static credentials
        self._mqtt_client_id = static_client_id
        self._username = DEFAULT_MQTT_USERNAME
        self._password = DEFAULT_MQTT_PASSWORD
        #self.client_id = DEFAULT_CLIENT_ID
        self._auth_method = None

        # Create new client with proper callbacks so _on_connect fires
        # and all topic subscriptions are registered
        self._client = mqtt.Client(
            client_id=static_client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
            transport="tcp",
            **_MQTT_CLIENT_KWARGS,
        )
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message
        #self._client.username_pw_set(DEFAULT_MQTT_USERNAME, DEFAULT_MQTT_PASSWORD)

        if self.use_ssl:
            cert = self._CERTS_DIR / DEFAULT_CERT_FILENAME
            key = self._CERTS_DIR / DEFAULT_KEY_FILENAME

            if os.path.exists(cert) and os.path.exists(key):
                # Use bundled client certificates (mutual TLS) — same as __init__
                self._client.username_pw_set(DEFAULT_MQTT_USERNAME, DEFAULT_MQTT_PASSWORD)
                self._client.tls_set(
                    ca_certs=None,
                    certfile=str(cert),
                    keyfile=str(key),
                    cert_reqs=ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLS,
                )
                self._client.tls_insecure_set(True)
            else:
                self._client.username_pw_set(DEFAULT_MQTT_USERNAME, DEFAULT_MQTT_PASSWORD)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self._client.tls_set_context(context)

        # Stop old client before connecting new one
        try:
            old_client.loop_stop()
            old_client.disconnect()
        except Exception:
            pass

        try:
            self._connected = False
            self._client.connect(self.host, self.port, keepalive=60)
            self._client.loop_start()

            start = time.time()
            while not self._connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if self._connected:
                _LOGGER.info("Connected with static credentials!")
                return True

            # Failed — stop loop
            self._client.loop_stop()
            try:
                self._client.disconnect()
            except Exception:
                pass

        except Exception as e:
            _LOGGER.debug("Static connect failed: %s", e)
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass

        # Restore old state on failure
        self._mqtt_client_id = old_mqtt_client_id
        self._username = old_username
        self._password = old_password
        self.client_id = old_client_id
        self._auth_method = old_auth_method
        self._client = old_client
        return False

    def _connect_with_fallback(self, timeout: float = 10.0, auto_refresh: bool = True) -> bool:
        """Try connecting with different auth methods until one works.

        Tries static credentials first (works on Toshiba/VIDAA licensed models),
        then falls back to dynamic auth methods, then static again after a delay
        in case of rate limiting.
        """
        auth_methods = get_auth_method_order()

        # Skip the method we already tried
        if self._auth_method in auth_methods:
            auth_methods = [m for m in auth_methods if m != self._auth_method]

        # Try static credentials first — works on Toshiba/VIDAA licensed TVs
        # that reject dynamic auth entirely, and avoids triggering rate limiting
        _LOGGER.info("Trying static credentials first...")
        if self._try_static_connect(timeout=timeout):
            return True
        _LOGGER.info("Static credentials failed, trying dynamic auth methods...")

        for method in auth_methods:
            _LOGGER.info("Trying %s authentication...", method.value)
            self._auth_method = method

            creds = generate_credentials(
                mac_address=self.mac_address,
                brand=self.brand,
                auth_method=method,
            )

            self._mqtt_client_id = creds.client_id
            self._username = creds.username
            self._password = creds.password
            self.client_id = creds.client_id

            self._client = mqtt.Client(
                client_id=self._mqtt_client_id,
                clean_session=True,
                protocol=mqtt.MQTTv311,
                transport="tcp",
                **_MQTT_CLIENT_KWARGS,
            )
            self._client.on_connect = self._on_connect
            self._client.on_disconnect = self._on_disconnect
            self._client.on_message = self._on_message

            if self.use_ssl:
                cert = self._CERTS_DIR / DEFAULT_CERT_FILENAME
                key = self._CERTS_DIR / DEFAULT_KEY_FILENAME
                if os.path.exists(cert) and os.path.exists(key):
                    self._client.username_pw_set(self._username, self._password)
                    self._client.tls_set(
                        ca_certs=None,
                        certfile=str(cert),
                        keyfile=str(key),
                        cert_reqs=ssl.CERT_NONE,
                        tls_version=ssl.PROTOCOL_TLS,
                    )
                    self._client.tls_insecure_set(True)
                else:
                    self._client.username_pw_set(self._username, self._password)
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self._client.tls_set_context(context)
            else:
                self._client.username_pw_set(self._username, self._password)

            try:
                self._client.connect(self.host, self.port, keepalive=60)
                self._client.loop_start()

                start = time.time()
                while not self._connected and (time.time() - start) < timeout:
                    time.sleep(0.1)

                if self._connected:
                    _LOGGER.info("Connected successfully with %s authentication!", method.value)
                    if auto_refresh and self._pending_token_refresh:
                        if not self.refresh_token(timeout=timeout):
                            _LOGGER.warning("Token refresh failed")
                    return True
                else:
                    self._client.loop_stop()
                    self._client.disconnect()
            except Exception as e:
                _LOGGER.debug("  %s auth failed: %s", method.value, e)
                try:
                    self._client.loop_stop()
                    self._client.disconnect()
                except Exception:
                    pass

        # Final fallback: static credentials again after waiting for rate limit to clear
        _LOGGER.info("All dynamic auth methods failed. Waiting for TV rate limit to clear...")
        time.sleep(5)
        _LOGGER.info("Retrying static credentials after cooldown...")
        if self._try_static_connect(timeout=timeout):
            return True

        _LOGGER.error("All authentication methods failed including static fallback")
        return False

    def disconnect(self):
        """Disconnect from the TV."""
        self._client.loop_stop()
        self._client.disconnect()
        self._connected = False

    def _verify_server_cert_tofu(self):
        """Trust-On-First-Use server certificate verification."""
        try:
            sock = self._client.socket()
            if not isinstance(sock, ssl.SSLSocket):
                return

            der_cert = sock.getpeercert(binary_form=True)
            if not der_cert:
                return

            fingerprint = hashlib.sha256(der_cert).hexdigest()

            if self._storage:
                stored_fp = self._storage.get_cert_fingerprint(
                    device_id=self.mac_address, host=self.host, port=self.port,
                )
                if stored_fp and stored_fp != fingerprint:
                    _LOGGER.warning(
                        "TV certificate fingerprint changed! "
                        "This could indicate a MITM attack or TV firmware update. "
                        "Stored: %s..., Got: %s...",
                        stored_fp[:16], fingerprint[:16],
                    )
                elif not stored_fp:
                    self._storage.save_cert_fingerprint(
                        fingerprint,
                        device_id=self.mac_address, host=self.host, port=self.port,
                    )
                    _LOGGER.debug("Stored server certificate fingerprint (TOFU)")
        except Exception as err:
            _LOGGER.debug("Could not verify server certificate: %s", err)

    def _on_connect(self, client, userdata, flags, rc):
        """Handle connection callback."""
        if rc == 0:
            self._connected = True
            _LOGGER.info("Connected to TV at %s:%s", self.host, self.port)

            self._verify_server_cert_tofu()

            self._client.subscribe(TOPIC_STATE_RESPONSE)
            self._client.subscribe(TOPIC_VOLUME_RESPONSE)
            self._client.subscribe("/remoteapp/mobile/broadcast/platform_service/actions/volumechange")
            self._client.subscribe(get_topic(TOPIC_SOURCES_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_APPS_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_AUTH_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_AUTH_CODE_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_TOKEN_RESPONSE, self.client_id))
            self._client.subscribe("/remoteapp/mobile/broadcast/ui_service/state")
            self._client.subscribe(get_topic(TOPIC_TV_INFO_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_DEVICE_INFO_RESPONSE, self.client_id))
            self._client.subscribe(get_topic(TOPIC_CAPABILITY_RESPONSE, self.client_id))

            if self._access_token:
                self._authenticated = True
        else:
            _LOGGER.error("Connection failed with code: %s", rc)

    def _on_disconnect(self, client, userdata, rc):
        """Handle disconnection callback."""
        self._connected = False

    def _on_message(self, client, userdata, msg):
        """Handle incoming messages."""
        try:
            payload = json.loads(msg.payload.decode())

            if "tokenissuance" in msg.topic:
                self._last_response = payload
                self._response_event.set()
                self._handle_token_response(payload)
            elif "authentication" in msg.topic:
                self._last_response = payload
                self._response_event.set()
                self._handle_auth_response(payload)
            elif "/volume" in msg.topic or "volumechange" in msg.topic:
                _LOGGER.debug("Volume response on %s: %s", msg.topic, payload)
                volume_type = payload.get("volume_type", 0)
                if volume_type == 0:
                    for field in ["volume_value", "volume", "value"]:
                        if field in payload:
                            try:
                                self._cached_volume = int(payload[field])
                                break
                            except (ValueError, TypeError):
                                pass
                elif volume_type == 2:
                    mute_val = payload.get("volume_value", 0)
                    self._cached_muted = (mute_val == 1)
                self._last_response = payload
                self._response_event.set()
            elif "broadcast" in msg.topic:
                self._state = payload
                if payload.get("statetype") == "authentication":
                    self._auth_required = True
                    if self.on_auth_required:
                        self.on_auth_required()
                if self.on_state_change:
                    self.on_state_change(payload)
            else:
                self._last_response = payload
                self._response_event.set()
        except json.JSONDecodeError:
            self._last_response = {"raw": msg.payload.decode()}
            self._response_event.set()

    def _handle_auth_response(self, payload):
        """Handle authentication response from TV."""
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                _LOGGER.debug("Auth response is non-JSON string: %s", payload)
                return

        if payload.get("result") == 1:
            self._authenticated = True
            self._auth_required = False
            self._auth_event.set()
        elif payload.get("statetype") == "authenticationcode":
            self._auth_required = True
            if self.on_auth_required:
                self.on_auth_required()

    def _handle_token_response(self, payload: dict):
        """Handle token issuance response from TV."""
        access_token = payload.get("accesstoken")
        refresh_token = payload.get("refreshtoken")

        if access_token:
            self._access_token = access_token
            self._authenticated = True
            self._auth_required = False

            if self._storage:
                device_id = self.mac_address or self.host
                self._storage.save_token(
                    device_id=device_id,
                    host=self.host,
                    port=self.port,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    access_token_duration_days=payload.get("accesstoken_duration_day", 7),
                    refresh_token_duration_days=payload.get("refreshtoken_duration_day", 30),
                    client_id=self._mqtt_client_id,
                    mqtt_username=self._username,
                    uuid=self.mac_address,
                    auth_method=self._auth_method.value if self._auth_method else None,
                    protocol_version=self._protocol_version,
                )

            _LOGGER.info("Token received and saved!")
            self._auth_event.set()

    def _publish(self, topic: str, payload: Any = "") -> bool:
        """Publish a message to the TV."""
        if not self._connected:
            _LOGGER.warning("Not connected to TV")
            return False

        if isinstance(payload, dict):
            payload = json.dumps(payload)

        result = self._client.publish(topic, payload)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def _request(self, topic: str, payload: Any = "", timeout: float = 5.0) -> Optional[dict]:
        """Send a request and wait for response."""
        self._response_event.clear()
        self._last_response = None

        if not self._publish(topic, payload):
            return None

        if self._response_event.wait(timeout):
            return self._last_response
        return None

    def authenticate(self, pin: str, wait_for_response: bool = True, timeout: float = 10.0) -> bool:
        """Send authentication PIN displayed on TV."""
        self._auth_event.clear()
        topic = get_topic(TOPIC_AUTH, self.client_id)

        try:
            pin_int = int(pin)
        except ValueError:
            _LOGGER.error("Invalid PIN: %s", pin)
            return False

        if not self._publish(topic, {"authNum": pin_int}):
            return False

        if wait_for_response:
            if self._auth_event.wait(timeout):
                if self._authenticated:
                    self._request_token()
                return self._authenticated
            return False

        return True

    def _request_token(self, refresh_token: str = ""):
        """Request access token (new or refreshed)."""
        topic = get_topic(TOPIC_GET_TOKEN, self.client_id)
        self._publish(topic, {"refreshtoken": refresh_token})

        if not refresh_token:
            close_topic = get_topic(TOPIC_AUTH_CLOSE, self.client_id)
            self._publish(close_topic, "")

    def refresh_token(self, timeout: float = 10.0) -> bool:
        """Refresh the access token using the refresh token."""
        if not self._refresh_token:
            _LOGGER.warning("No refresh token available")
            return False

        if not self._connected:
            _LOGGER.warning("Must be connected to refresh token")
            return False

        self._auth_event.clear()
        _LOGGER.info("Refreshing access token...")
        self._request_token(self._refresh_token)

        if self._auth_event.wait(timeout):
            if self._access_token:
                _LOGGER.info("Token refreshed successfully!")
                self._password = self._access_token
                self._pending_token_refresh = False
                return True

        _LOGGER.warning("Token refresh failed")
        return False

    def start_pairing(self) -> bool:
        """Start the pairing process to show PIN on TV."""
        self._client.subscribe(get_topic(TOPIC_AUTH_RESPONSE, self.client_id))
        self._client.subscribe(get_topic(TOPIC_AUTH_CODE_RESPONSE, self.client_id))
        self._client.subscribe(get_topic(TOPIC_TOKEN_RESPONSE, self.client_id))

        topic = get_topic(TOPIC_VIDAA_CONNECT, self.client_id)
        return self._publish(topic, {
            "app_version": 2,
            "connect_result": 0,
            "device_type": "Mobile App"
        })

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with the TV."""
        return self._authenticated

    def needs_authentication(self) -> bool:
        """Check if TV is requesting authentication."""
        return self._auth_required

    def clear_saved_token(self):
        """Clear saved authentication token for this TV."""
        if self._storage:
            self._storage.delete_token(self.host, self.port)
        self._access_token = None
        self._authenticated = False

    def get_saved_token_info(self) -> Optional[dict]:
        """Get information about saved token for this TV."""
        if self._storage:
            return self._storage.get_token(self.host, self.port)
        return None

    def _is_tv_on(self, timeout: float = 3.0) -> bool:
        """Check if TV is powered on (not in fake_sleep state)."""
        state = self.get_state(timeout=timeout)
        if state and state.get("statetype") == "fake_sleep_0":
            return False
        return state is not None

    def is_on(self) -> bool:
        """Check if TV is currently powered on."""
        return self._is_tv_on()

    def send_key(self, key: str, check_state: bool = False) -> bool:
        """Send a remote key press."""
        if check_state and key != "KEY_POWER":
            if not self._is_tv_on():
                _LOGGER.debug("TV is off. Command not sent.")
                return False

        topic = get_topic(TOPIC_SEND_KEY, self.client_id)
        return self._publish(topic, key)

    def power(self) -> bool:
        """Toggle power."""
        return self.send_key("KEY_POWER")

    def power_on(self) -> bool:
        """Turn TV on (only if it's off)."""
        state = self.get_state(timeout=3.0)
        if state and state.get("statetype") == "fake_sleep_0":
            return self.send_key("KEY_POWER")
        elif state:
            _LOGGER.debug("TV is already on.")
            return True
        else:
            return self.send_key("KEY_POWER")

    def power_off(self) -> bool:
        """Turn TV off (only if it's on)."""
        state = self.get_state(timeout=3.0)
        if state and state.get("statetype") != "fake_sleep_0":
            return self.send_key("KEY_POWER")
        elif state:
            _LOGGER.debug("TV is already off.")
            return True
        else:
            _LOGGER.warning("Could not determine TV state.")
            return False

    def volume_up(self) -> bool:
        """Increase volume."""
        return self.send_key("KEY_VOLUMEUP")

    def volume_down(self) -> bool:
        """Decrease volume."""
        return self.send_key("KEY_VOLUMEDOWN")

    def mute(self) -> bool:
        """Toggle mute."""
        return self.send_key("KEY_MUTE")

    def up(self) -> bool:
        """Navigate up."""
        return self.send_key("KEY_UP")

    def down(self) -> bool:
        """Navigate down."""
        return self.send_key("KEY_DOWN")

    def left(self) -> bool:
        """Navigate left."""
        return self.send_key("KEY_LEFT")

    def right(self) -> bool:
        """Navigate right."""
        return self.send_key("KEY_RIGHT")

    def ok(self) -> bool:
        """Press OK/Enter."""
        return self.send_key("KEY_OK")

    def back(self) -> bool:
        """Go back."""
        return self.send_key("KEY_RETURNS")

    def menu(self) -> bool:
        """Open menu."""
        return self.send_key("KEY_MENU")

    def home(self) -> bool:
        """Go to home screen."""
        return self.send_key("KEY_HOME")

    def exit(self) -> bool:
        """Exit current screen."""
        return self.send_key("KEY_EXIT")

    def play(self) -> bool:
        """Play."""
        return self.send_key("KEY_PLAY")

    def pause(self) -> bool:
        """Pause."""
        return self.send_key("KEY_PAUSE")

    def stop(self) -> bool:
        """Stop."""
        return self.send_key("KEY_STOP")

    def get_volume(self, timeout: float = 5.0) -> Optional[int]:
        """Get current volume level (0-100)."""
        topic = get_topic(TOPIC_GET_VOLUME, self.client_id)
        deadline = time.time() + timeout
        self._response_event.clear()
        self._publish(topic)
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            if self._response_event.wait(timeout=remaining):
                self._response_event.clear()
                response = self._last_response
                if response and isinstance(response, dict):
                    volume_type = response.get("volume_type", 0)
                    if volume_type == 0:
                        for field in ["volume_value", "volume", "value"]:
                            if field in response:
                                try:
                                    vol = int(response[field])
                                    self._cached_volume = vol
                                    return vol
                                except (ValueError, TypeError):
                                    pass
                    _LOGGER.debug("Volume response: type=%s, data=%s", volume_type, response)
            else:
                break

        if self._cached_volume is not None:
            _LOGGER.debug("Using cached volume: %s", self._cached_volume)
            return self._cached_volume
        return None

    @property
    def cached_volume(self) -> Optional[int]:
        """Get last known volume from broadcasts."""
        return self._cached_volume

    @property
    def is_muted(self) -> bool:
        """Get mute status from broadcasts."""
        return self._cached_muted

    def set_volume(self, level: int, check_state: bool = False) -> bool:
        """Set volume level (0-100)."""
        if check_state and not self._is_tv_on():
            print("TV is off. Command not sent.")
            return False

        level = max(0, min(100, level))
        topic = get_topic(TOPIC_SET_VOLUME, self.client_id)
        return self._publish(topic, str(level))

    def get_sources(self, timeout: float = 5.0) -> Optional[list]:
        """Get available input sources."""
        topic = get_topic(TOPIC_GET_SOURCES, self.client_id)
        return self._request(topic, timeout=timeout)

    def set_source(self, source: str, check_state: bool = False) -> bool:
        """Set input source."""
        if check_state and not self._is_tv_on():
            print("TV is off. Command not sent.")
            return False

        source_id = SOURCE_MAP.get(source.lower(), source)
        topic = get_topic(TOPIC_SET_SOURCE, self.client_id)
        return self._publish(topic, {"sourceid": source_id})

    def get_state(self, timeout: float = 5.0) -> Optional[dict]:
        """Get TV state information."""
        old_state = self._state

        topic = get_topic(TOPIC_GET_STATE, self.client_id)
        self._publish(topic, "")

        start = time.time()
        while time.time() - start < timeout:
            if self._state and self._state != old_state:
                return self._state
            time.sleep(0.1)

        return self._state

    def get_tv_info(self, timeout: float = 5.0) -> Optional[dict]:
        """Get TV info (chipplatform, brand, features, etc)."""
        topic = get_topic(TOPIC_GET_TV_INFO, self.client_id)
        return self._request(topic, timeout=timeout)

    def get_device_info(self, timeout: float = 5.0) -> Optional[dict]:
        """Get device info (model, name, version, etc)."""
        topic = get_topic(TOPIC_GET_DEVICE_INFO, self.client_id)
        return self._request(topic, timeout=timeout)

    def get_capability(self, timeout: float = 5.0) -> Optional[dict]:
        """Get TV capabilities and software versions."""
        topic = get_topic(TOPIC_GET_CAPABILITY, self.client_id)
        return self._request(topic, timeout=timeout)

    def get_apps(self, timeout: float = 5.0) -> Optional[list]:
        """Get list of available apps."""
        apps_response = []
        apps_received = threading.Event()

        def on_apps_message(client, userdata, msg):
            nonlocal apps_response
            if "applist" in msg.topic:
                try:
                    apps_response = json.loads(msg.payload.decode())
                    apps_received.set()
                except json.JSONDecodeError:
                    pass

        apps_topic = get_topic(TOPIC_APPS_RESPONSE, self.client_id)
        self._client.message_callback_add(apps_topic, on_apps_message)

        try:
            topic = get_topic(TOPIC_GET_APPS, self.client_id)
            self._publish(topic, "")

            if apps_received.wait(timeout):
                return apps_response if isinstance(apps_response, list) else None
            return None
        finally:
            self._client.message_callback_remove(apps_topic)

    def launch_app(self, app_name: str, check_state: bool = False) -> bool:
        """Launch an app by name."""
        if check_state and not self._is_tv_on():
            print("TV is off. Command not sent.")
            return False

        if isinstance(app_name, dict):
            app_data = app_name
        elif app_name.lower() in APPS:
            app_data = APPS[app_name.lower()]
        else:
            app_list = self.get_apps()
            if app_list:
                for app in app_list:
                    if app.get("name", "").upper() == app_name.upper():
                        app_data = {
                            "appId": app.get("appId"),
                            "name": app.get("name"),
                            "url": app.get("url")
                        }
                        break
                else:
                    _LOGGER.warning("App '%s' not found. Use get_apps() to see available apps.", app_name)
                    return False
            else:
                _LOGGER.warning("Could not get app list. Try one of: netflix, youtube, amazon, disney, hulu")
                return False

        topic = get_topic(TOPIC_LAUNCH_APP, self.client_id)
        return self._publish(topic, app_data)

    @property
    def is_connected(self) -> bool:
        """Check if connected to TV."""
        return self._connected

    @property
    def state(self) -> dict:
        """Get last known TV state."""
        return self._state

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()