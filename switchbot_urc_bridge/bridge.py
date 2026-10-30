#!/usr/bin/env python3
"""SwitchBot URC Bridge add-on: fake native target for the WoRWS button channel.

Firmware analysis confirms that a native press makes the WoRWS act as a BLE central: it connects
to the MAC saved by 0F 20 08, discovers cba20d00/cba20002/cba20003, performs the 0F 21 03 session
handshake, and writes the encrypted device command. Advertisement scanning is therefore disabled
by default because sharing one controller between an active scan and a connectable peripheral can
prevent or delay the incoming connection on some adapters.

Config comes from environment variables set by run.sh:
  ADAPTER   e.g. hci1         Bluetooth adapter used for peripheral + diagnostic scan
  REMOTE_ADDRESS              BLE MAC of the physical WoRWS being observed
  NAME      e.g. "HASS Light" advertised name
  TOPIC     e.g. switchbot_urc/button
  DISCOVERY "true"/"false"    publish HA MQTT discovery
  DIAGNOSTIC_SCAN "true"/"false" scan WoRWS advertisements (normally keep false)
  HCI_TRACE "true"/"false"    log controller diagnostics plus one remote ATT session
  DEVICE_KEY 32 hex (optional) only needed if the remote->device link is encrypted
  MQTT_HOST/MQTT_PORT/MQTT_USER/MQTT_PASS  broker (from the MQTT service)
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import select
import signal
import socket
import struct
import subprocess
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_LOG = logging.getLogger("bridge")

SVC = "cba20d00-224d-11e6-9fb8-0002a5d5c51b"
CHAR_WRITE = "cba20002-224d-11e6-9fb8-0002a5d5c51b"
CHAR_NOTIFY = "cba20003-224d-11e6-9fb8-0002a5d5c51b"
FD3D = "0000fd3d-0000-1000-8000-00805f9b34fb"

# Linux Bluetooth Management API constants. The add-on already has NET_ADMIN and the bridge
# adapter is dedicated to peripheral mode, so loading a per-peer connection profile here avoids
# changing Home Assistant's host-wide bluetoothd configuration.
MGMT_OP_LOAD_CONN_PARAM = 0x0035
MGMT_OP_ADD_ADVERTISING = 0x003E
MGMT_OP_REMOVE_ADVERTISING = 0x003F
MGMT_OP_READ_DEF_SYSTEM_CONFIG = 0x004B
MGMT_OP_SET_DEF_SYSTEM_CONFIG = 0x004C
MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_CONTROL = 3

# WoRWS firmware passes 6, 0x50, 2, 0x190 to its BLE-central connect wrapper at ARM 0x12010.
# Hardware testing also proved that Linux's early L2CAP request for the narrower interval keeps
# ATT progressing through more of WoRWS's short discovery window, even though the final link
# update itself completes late. Keep the live-tested peripheral request from 0.11.12.
def _conn_units_from_env(name: str, default_units: int) -> int:
    """Parse a connection interval given in milliseconds into 1.25 ms units.

    The interval the WoRWS central actually uses is the single biggest driver of how much of its
    ~2 s discovery window a native press has left.  WoRWS has been observed ignoring the advertised
    range and running the CSR 4.0 link slowly, so exposing the requested range as an env option lets
    the interval be A/B tested on hardware (watch t_subscribe/t_write in the session summary) without
    code edits.  Values outside the valid 6..3200 unit span fall back to the live-tested default.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default_units
    try:
        units = round(float(raw) / 1.25)
    except ValueError:
        _LOG.warning("ignoring non-numeric %s=%r; using %d units", name, raw, default_units)
        return default_units
    if not 6 <= units <= 3200:
        _LOG.warning("ignoring out-of-range %s=%r; using %d units", name, raw, default_units)
        return default_units
    return units


WORWS_CONN_MIN = _conn_units_from_env("CONN_INTERVAL_MIN_MS", 6)   # 7.5 ms
WORWS_CONN_MAX = _conn_units_from_env("CONN_INTERVAL_MAX_MS", 12)  # 15 ms
if WORWS_CONN_MIN > WORWS_CONN_MAX:
    WORWS_CONN_MIN, WORWS_CONN_MAX = WORWS_CONN_MAX, WORWS_CONN_MIN
WORWS_CONN_LATENCY = 0
WORWS_CONN_TIMEOUT = 0x190
BRIDGE_ADV_INTERVAL = 0x0020  # 20 ms in Bluetooth's 0.625 ms units.
# Seconds a raw-ATT peer may stay silent before the single-connection server drops it.  Long
# enough never to interrupt a live press (which completes in well under a second) yet short enough
# that a wedged half-open link cannot starve the next press of its accept slot.
RAW_ATT_IDLE_TIMEOUT = 6.0
# WoRWS deliberately closes its native-target connection when its firmware transaction countdown
# expires.  Repeating the most recent valid application ACK refreshes that countdown without
# creating another HA event.  Keep this bounded so an idle remote does not stay connected forever.
RAW_ATT_KEEPALIVE_INTERVAL = 1.0
RAW_ATT_KEEPALIVE_WINDOW = 300.0

HCI_TRACE_MARKERS = (
    "LE Set Advertising",
    "LE Connection Complete",
    "LE Enhanced Connection Complete",
    "LE Connection Update Complete",
    "Connection Parameter Update",
    "Disconnect Complete",
)


def _interesting_hci_block(lines: list[str]) -> bool:
    """Return true for the small subset of btmon packets useful to this bridge."""
    block = "\n".join(lines)
    return any(marker in block for marker in HCI_TRACE_MARKERS)


def _hci_packet_start(line: str) -> bool:
    """Recognize btmon packet headers, including its optional ``[index]:`` prefix."""
    candidate = line.split("]: ", 1)[-1]
    return candidate.startswith(("< ", "> ", "@ ", "* "))


class HciTrace:
    """Run a filtered btmon stream and capture exactly one remote ATT session."""

    def __init__(self, adapter: str, remote_address: str | None = None) -> None:
        self.adapter = adapter
        self.remote_address = remote_address.upper() if remote_address else None
        self._process: subprocess.Popen[str] | None = None
        self._capture_att = False
        self._att_capture_done = False

    def start(self) -> None:
        try:
            self._process = subprocess.Popen(
                ["btmon", "-i", self.adapter],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except (FileNotFoundError, OSError) as err:
            _LOG.warning("could not start filtered HCI trace: %s", err)
            return
        threading.Thread(target=self._run, name="btmon-filter", daemon=True).start()
        _LOG.info("filtered HCI/ATT trace started on %s", self.adapter)

    def _run(self) -> None:
        assert self._process is not None
        assert self._process.stdout is not None
        block: list[str] = []
        for raw_line in self._process.stdout:
            line = raw_line.rstrip()
            if _hci_packet_start(line) and block:
                self._emit(block)
                block = []
            block.append(line)
        self._emit(block)
        return_code = self._process.wait()
        if return_code:
            _LOG.warning("filtered HCI trace stopped with exit code %s", return_code)

    def _emit(self, block: list[str]) -> None:
        if not block:
            return
        block_text = "\n".join(block)
        is_connection = (
            "Connection Complete" in block_text
            and "Status: Success" in block_text
            and (
                self.remote_address is None
                or f"Peer address: {self.remote_address}" in block_text
            )
        )
        if is_connection and not self._att_capture_done:
            self._capture_att = True
            _LOG.info("one-shot ATT capture started for %s", self.remote_address or "peer")

        if _interesting_hci_block(block) or (self._capture_att and "ATT:" in block_text):
            _LOG.info("HCI TRACE\n%s", block_text)

        if self._capture_att and "Disconnect Complete" in block_text:
            self._capture_att = False
            self._att_capture_done = True
            _LOG.info("one-shot ATT capture complete; further ATT discovery noise is suppressed")


def _dbus_bytes(value) -> str:
    """Render a D-Bus byte array without depending on dbus-python types at import time."""
    try:
        return bytes(int(item) & 0xFF for item in value).hex()
    except (TypeError, ValueError):
        return str(value)


def native_strip_advertisement(mac: str) -> tuple[list[int], list[int]]:
    """Return the FD3D and company-0x0969 payloads of an idle WoStrip."""
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(mac_bytes) != 6:
        raise ValueError("adapter MAC must contain exactly six bytes")

    # Preserve the identifying/status prefix but omit three trailing reserved zero bytes so the
    # standard six-byte Peripheral Connection Interval Range field fits in a 31-byte legacy ADV.
    manufacturer = list(mac_bytes) + [0x01, 0xE4, 0x22] + [0x00] * 4
    return [0x72], manufacturer


def peripheral_connection_interval_data(
    min_interval: int = WORWS_CONN_MIN, max_interval: int = WORWS_CONN_MAX
) -> dict[int, list[int]]:
    """Return AD type 0x12 requesting the configured connection interval range."""
    if not 6 <= min_interval <= max_interval <= 3200:
        raise ValueError("connection interval units must satisfy 6 <= min <= max <= 3200")
    return {0x12: list(struct.pack("<HH", min_interval, max_interval))}


def raw_native_advertisement(
    service_data: list[int], manufacturer_data: list[int]
) -> bytes:
    """Build the 28 user bytes for a native legacy advertisement.

    The kernel adds the three-byte Flags AD structure when the MGMT discoverable flag is set.
    Keeping that out of this payload leaves exactly 28 bytes for manufacturer data, FD3D service
    data, and the standard Peripheral Connection Interval Range field.
    """
    if len(service_data) != 1:
        raise ValueError("native FD3D service data must contain exactly one byte")
    if len(manufacturer_data) != 13:
        raise ValueError("native manufacturer data must contain exactly 13 bytes")
    manufacturer = bytes(
        [1 + 2 + len(manufacturer_data), 0xFF, 0x69, 0x09, *manufacturer_data]
    )
    service = bytes([1 + 2 + len(service_data), 0x16, 0x3D, 0xFD, *service_data])
    interval = bytes([0x05, 0x12, *peripheral_connection_interval_data()[0x12]])
    payload = manufacturer + service + interval
    if len(payload) > 28:
        raise ValueError("raw advertisement exceeds the 28-byte MGMT discoverable budget")
    return payload


def fast_advertisement_class(base_class, dbus_module, interval_ms: int = 100):
    """Extend Bluezero's fallback advertisement with a fast advertising interval."""
    if not 20 <= interval_ms <= 10_485:
        raise ValueError("advertising interval must be between 20 and 10485 ms")

    class FastAdvertisement(base_class):
        @dbus_module.service.method(
            "org.freedesktop.DBus.Properties",
            in_signature="s",
            out_signature="a{sv}",
        )
        def GetAll(self, interface_name):  # noqa: N802 - D-Bus API name
            response = super().GetAll(interface_name)
            if interface_name == self.interface:
                response["MinInterval"] = dbus_module.UInt32(interval_ms)
                response["MaxInterval"] = dbus_module.UInt32(interval_ms)
            return response

    return FastAdvertisement


def resolve_bluez_adapter(selector: str) -> tuple[str, str]:
    """Resolve either ``hciN`` or a controller MAC to ``(hciN, MAC)`` via BlueZ."""
    import dbus

    bus = dbus.SystemBus()
    manager_obj = bus.get_object("org.bluez", "/")
    manager = dbus.Interface(manager_obj, "org.freedesktop.DBus.ObjectManager")
    managed = manager.GetManagedObjects()
    wanted = selector.strip()
    wanted_address = wanted.upper()
    available: list[str] = []
    for path, interfaces in managed.items():
        properties = dict(interfaces).get("org.bluez.Adapter1")
        if not properties:
            continue
        name = str(path).rsplit("/", 1)[-1]
        address = str(properties.get("Address", "")).upper()
        available.append(f"{name}={address}")
        if name == wanted or address == wanted_address:
            return name, address
    raise RuntimeError(
        f"BlueZ adapter {selector!r} was not found; available adapters: "
        + ", ".join(available)
    )


def _open_mgmt_socket():
    """Open an HCI control-channel socket on Python versions predating its socket API support."""
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_hci = getattr(socket, "BTPROTO_HCI", 1)
    sock_type = socket.SOCK_RAW | getattr(socket, "SOCK_CLOEXEC", 0)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.socket(af_bluetooth, sock_type, btproto_hci)
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    address = struct.pack("=HHH", af_bluetooth, HCI_DEV_NONE, HCI_CHANNEL_CONTROL)
    try:
        if libc.bind(fd, address, len(address)) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return socket.socket(af_bluetooth, sock_type, btproto_hci, fileno=fd)
    except Exception:
        os.close(fd)
        raise


def load_remote_connection_parameters(
    adapter: str,
    remote_address: str,
    min_interval: int = WORWS_CONN_MIN,
    max_interval: int = WORWS_CONN_MAX,
    latency: int = WORWS_CONN_LATENCY,
    supervision_timeout: int = WORWS_CONN_TIMEOUT,
    response_timeout: float = 3.0,
) -> bool:
    """Load the live-tested LE connection request for this peer into the Linux kernel.

    Intervals are in 1.25 ms units and the supervision timeout is in 10 ms units. Although the
    accepted link update completes late, a direct 0.11.13 comparison proved that suppressing its
    early signaling exchange makes WoRWS abandon ATT even sooner. Keep the successful 0.11.12
    behavior while the compact service database removes a real discovery round trip.
    """
    try:
        adapter_index = int(adapter.removeprefix("hci"))
        address = bytes.fromhex(remote_address.replace(":", "").replace("-", ""))
        if len(address) != 6:
            raise ValueError("remote address must contain exactly six bytes")
        if not (6 <= min_interval <= max_interval <= 3200):
            raise ValueError("invalid LE connection interval range")
        if not (0 <= latency <= 499 and 10 <= supervision_timeout <= 3200):
            raise ValueError("invalid LE latency or supervision timeout")

        # mgmt uses Linux's little-endian bdaddr_t representation, followed by LE Public (0x01).
        entry = (
            address[::-1]
            + bytes([0x01])
            + struct.pack("<HHHH", min_interval, max_interval, latency, supervision_timeout)
        )
        payload = struct.pack("<H", 1) + entry
        packet = struct.pack(
            "<HHH", MGMT_OP_LOAD_CONN_PARAM, adapter_index, len(payload)
        ) + payload

        with _open_mgmt_socket() as mgmt:
            mgmt.settimeout(response_timeout)
            mgmt.send(packet)
            deadline = time.monotonic() + response_timeout
            while time.monotonic() < deadline:
                event = mgmt.recv(1024)
                if len(event) < 6:
                    continue
                event_code, event_index, event_len = struct.unpack_from("<HHH", event)
                body = event[6:6 + event_len]
                if event_index != adapter_index or len(body) < 3:
                    continue
                if event_code in (MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS):
                    command, status = struct.unpack_from("<HB", body)
                else:
                    continue
                if command != MGMT_OP_LOAD_CONN_PARAM:
                    continue
                if status:
                    _LOG.warning(
                        "kernel rejected WoRWS connection parameters (MGMT status=0x%02x)",
                        status,
                    )
                    return False
                _LOG.info(
                    "configured WoRWS connection parameters on %s for %s "
                    "(interval=%.2f-%.2fms latency=%s timeout=%sms)",
                    adapter,
                    remote_address.upper(),
                    min_interval * 1.25,
                    max_interval * 1.25,
                    latency,
                    supervision_timeout * 10,
                )
                return True
        _LOG.warning("kernel did not answer the WoRWS connection-parameter request")
    except (OSError, TimeoutError, ValueError) as err:
        # This optimization is best-effort. Advertising/GATT must still start on older kernels.
        _LOG.warning("could not configure fast WoRWS connection parameters: %s", err)
    return False


def _mgmt_command(
    adapter: str, opcode: int, payload: bytes = b"", response_timeout: float = 3.0
) -> tuple[int, bytes]:
    """Send one Linux Bluetooth Management command and return ``(status, response)``."""
    adapter_index = int(adapter.removeprefix("hci"))
    packet = struct.pack("<HHH", opcode, adapter_index, len(payload)) + payload
    with _open_mgmt_socket() as mgmt:
        mgmt.settimeout(response_timeout)
        mgmt.send(packet)
        deadline = time.monotonic() + response_timeout
        while time.monotonic() < deadline:
            event = mgmt.recv(4096)
            if len(event) < 9:
                continue
            event_code, event_index, event_len = struct.unpack_from("<HHH", event)
            body = event[6:6 + event_len]
            if event_index != adapter_index or len(body) < 3:
                continue
            if event_code not in (MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS):
                continue
            command, status = struct.unpack_from("<HB", body)
            if command == opcode:
                return status, body[3:]
    raise TimeoutError(f"MGMT command 0x{opcode:04x} timed out")


class RawMgmtAdvertiser:
    """Publish one legacy advertisement without BlueZ's restrictive D-Bus parser.

    Home Assistant OS's bluetoothd rejects the standard AD type 0x12 when supplied through the
    LEAdvertisement1 ``Data`` dictionary. The kernel MGMT API accepts the same valid bytes and
    still coexists with BlueZ's D-Bus GATT application on this dedicated controller.
    """

    def __init__(self, adapter: str, advertisement: bytes, instance: int = 1) -> None:
        if not 1 <= instance <= 0xFF:
            raise ValueError("advertising instance must be between 1 and 255")
        if len(advertisement) > 28:
            raise ValueError("discoverable MGMT advertisement must not exceed 28 bytes")
        self.adapter = adapter
        self.advertisement = advertisement
        self.instance = instance
        self.active = False
        self._lock = threading.Lock()

    def register(self) -> bool:
        """Add or replace the raw connectable/discoverable advertising instance."""
        with self._lock:
            return self._register_locked()

    def _register_locked(self) -> bool:
        if self.active:
            return True
        # Connectable + Discoverable. Discoverable tells the kernel to prepend the Flags AD
        # structure, leaving the supplied 28 bytes untouched.
        flags = 0x00000003
        payload = struct.pack(
            "<BIHHBB",
            self.instance,
            flags,
            0,  # duration: remain active
            0,  # timeout: remain active
            len(self.advertisement),
            0,  # no scan response
        ) + self.advertisement
        status, response = _mgmt_command(
            self.adapter, MGMT_OP_ADD_ADVERTISING, payload
        )
        if status:
            raise RuntimeError(f"MGMT Add Advertising rejected with status 0x{status:02x}")
        returned_instance = response[0] if response else self.instance
        if returned_instance != self.instance:
            raise RuntimeError(
                f"MGMT Add Advertising returned unexpected instance {returned_instance}"
            )
        self.active = True
        _LOG.info(
            "raw MGMT advertisement registered (instance=%s bytes=%s)",
            self.instance,
            self.advertisement.hex(),
        )
        return True

    def remove(self) -> None:
        """Best-effort removal used during normal add-on shutdown."""
        with self._lock:
            if not self.active:
                return
            try:
                status, _response = _mgmt_command(
                    self.adapter,
                    MGMT_OP_REMOVE_ADVERTISING,
                    bytes([self.instance]),
                    response_timeout=1.0,
                )
                if status:
                    _LOG.warning(
                        "kernel rejected advertisement removal (MGMT status=0x%02x)", status
                    )
                else:
                    _LOG.info("raw MGMT advertisement removed")
            except (OSError, TimeoutError) as err:
                _LOG.warning("could not remove raw MGMT advertisement: %s", err)
            finally:
                self.active = False


def _connection_config_tlvs(
    min_interval: int,
    max_interval: int,
    latency: int,
    supervision_timeout: int,
    advertising_interval: int = BRIDGE_ADV_INTERVAL,
) -> bytes:
    """Encode LE advertising and default-connection values as MGMT configuration TLVs."""
    return b"".join(
        struct.pack("<HBH", parameter_type, 2, value)
        for parameter_type, value in (
            (0x000A, advertising_interval),
            (0x000B, advertising_interval),
            (0x0017, min_interval),
            (0x0018, max_interval),
            (0x0019, latency),
            (0x001A, supervision_timeout),
        )
    )


def _parse_mgmt_tlvs(payload: bytes) -> dict[int, bytes]:
    """Decode MGMT configuration TLVs, ignoring a truncated final entry."""
    result: dict[int, bytes] = {}
    offset = 0
    while offset + 3 <= len(payload):
        parameter_type, length = struct.unpack_from("<HB", payload, offset)
        offset += 3
        if offset + length > len(payload):
            break
        result[parameter_type] = payload[offset:offset + length]
        offset += length
    return result


def set_adapter_connection_parameters(
    adapter: str,
    min_interval: int = WORWS_CONN_MIN,
    max_interval: int = WORWS_CONN_MAX,
    latency: int = WORWS_CONN_LATENCY,
    supervision_timeout: int = WORWS_CONN_TIMEOUT,
    advertising_interval: int = BRIDGE_ADV_INTERVAL,
) -> bool:
    """Set and verify LE defaults on the dedicated bridge controller only."""
    if not (6 <= min_interval <= max_interval <= 3200):
        raise ValueError("invalid LE connection interval range")
    if not (0 <= latency <= 499 and 10 <= supervision_timeout <= 3200):
        raise ValueError("invalid LE latency or supervision timeout")
    if not 0x0020 <= advertising_interval <= 0x4000:
        raise ValueError("invalid LE advertising interval")
    wanted = {
        0x000A: advertising_interval,
        0x000B: advertising_interval,
        0x0017: min_interval,
        0x0018: max_interval,
        0x0019: latency,
        0x001A: supervision_timeout,
    }
    try:
        status, _response = _mgmt_command(
            adapter,
            MGMT_OP_SET_DEF_SYSTEM_CONFIG,
            _connection_config_tlvs(
                min_interval,
                max_interval,
                latency,
                supervision_timeout,
                advertising_interval,
            ),
        )
        if status:
            _LOG.warning(
                "kernel rejected bridge-adapter connection defaults (MGMT status=0x%02x)",
                status,
            )
            return False
        status, response = _mgmt_command(adapter, MGMT_OP_READ_DEF_SYSTEM_CONFIG)
        if status:
            _LOG.warning(
                "could not verify bridge-adapter connection defaults (MGMT status=0x%02x)",
                status,
            )
            return False
        decoded = _parse_mgmt_tlvs(response)
        actual = {
            parameter_type: struct.unpack("<H", decoded.get(parameter_type, b"\xff\xff"))[0]
            for parameter_type in wanted
        }
        if actual != wanted:
            _LOG.warning(
                "bridge-adapter connection defaults did not stick: wanted=%s actual=%s",
                wanted,
                actual,
            )
            return False
        _LOG.info(
            "configured bridge adapter %s LE defaults "
            "(advertising=%.2fms connection=%.2f-%.2fms latency=%s "
            "timeout=%sms; read-back verified)",
            adapter,
            advertising_interval * 0.625,
            min_interval * 1.25,
            max_interval * 1.25,
            latency,
            supervision_timeout * 10,
        )
        return True
    except (OSError, TimeoutError) as err:
        _LOG.warning("could not configure bridge-adapter connection defaults: %s", err)
        return False


def prewarm_remote_gatt_cache(
    adapter: str, remote_address: str, discovery_timeout: float = 20.0
) -> bool:
    """Cache WoRWS services before entering peripheral mode.

    BlueZ enables reverse service discovery by default: after an incoming LE connection it also
    behaves as a GATT client. WoRWS has a short target-discovery deadline, and the two simultaneous
    ATT discovery streams can make it disconnect just before subscribing to our notify CCCD.
    Making the known remote persistent and resolving its services once gives BlueZ a stored GATT
    database, greatly reducing the reverse-discovery work on the later incoming connection.
    """
    import dbus

    bus = dbus.SystemBus()
    manager_obj = bus.get_object("org.bluez", "/")
    manager = dbus.Interface(manager_obj, "org.freedesktop.DBus.ObjectManager")
    adapter_path = f"/org/bluez/{adapter}"
    adapter_obj = bus.get_object("org.bluez", adapter_path)
    adapter_iface = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
    wanted = remote_address.upper()
    started_discovery = False

    def find_device():
        for path, interfaces in manager.GetManagedObjects().items():
            props = dict(interfaces).get("org.bluez.Device1")
            if (
                props
                and str(path).startswith(adapter_path + "/")
                and str(props.get("Address", "")).upper() == wanted
            ):
                return str(path), dict(props)
        return None, None

    try:
        path, properties = find_device()
        if path is None:
            adapter_iface.SetDiscoveryFilter(
                {"Transport": dbus.String("le"), "DuplicateData": dbus.Boolean(False)}
            )
            try:
                adapter_iface.StartDiscovery()
                started_discovery = True
            except dbus.exceptions.DBusException as err:
                if "InProgress" not in err.get_dbus_name():
                    raise
            deadline = time.monotonic() + discovery_timeout
            while time.monotonic() < deadline:
                path, properties = find_device()
                if path is not None:
                    break
                time.sleep(0.25)
        if path is None or properties is None:
            _LOG.warning(
                "GATT cache prewarm skipped: WoRWS %s was not observed on %s within %.0fs",
                wanted, adapter, discovery_timeout,
            )
            return False

        device_obj = bus.get_object("org.bluez", path)
        device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
        device_iface = dbus.Interface(device_obj, "org.bluez.Device1")
        # Trusted=false devices discovered only for this warmup remain temporary and BlueZ may
        # discard both the object and its cached database before the first button press.
        device_props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
        if not bool(properties.get("ServicesResolved", False)):
            if started_discovery:
                try:
                    adapter_iface.StopDiscovery()
                except dbus.exceptions.DBusException:
                    pass
                started_discovery = False
                # BlueZ may abort a connection locally when it is requested in the same instant
                # that LE discovery is being stopped. Let the controller reach its idle state.
                time.sleep(1.0)
            resolved = False
            for attempt in range(1, 4):
                _LOG.info(
                    "prewarming WoRWS GATT cache on %s (%s), attempt %s/3",
                    adapter, wanted, attempt,
                )
                _path, current = find_device()
                try:
                    if not current or not bool(current.get("Connected", False)):
                        device_iface.Connect()
                except dbus.exceptions.DBusException as err:
                    # le-connection-abort-by-local is frequently delivered just before BlueZ
                    # reports the delayed connection. Do not tear down startup immediately;
                    # observe the Device1 state and retry after it settles.
                    _LOG.warning("GATT cache prewarm connect attempt %s: %s", attempt, err)
                deadline = time.monotonic() + 12.0
                while time.monotonic() < deadline:
                    _path, current = find_device()
                    if current and bool(current.get("ServicesResolved", False)):
                        resolved = True
                        break
                    # A delayed connection may appear after Connect already returned Failed.
                    # Keep waiting while connected; otherwise allow a short grace period before
                    # starting the next attempt.
                    time.sleep(0.2)
                try:
                    _path, current = find_device()
                    if current and bool(current.get("Connected", False)):
                        device_iface.Disconnect()
                except dbus.exceptions.DBusException:
                    pass
                if resolved:
                    break
                time.sleep(1.0)
            if not resolved:
                _LOG.warning("GATT cache prewarm failed after three connection attempts")
                return False
        _LOG.info("WoRWS GATT cache is ready")
        return True
    except Exception as err:  # noqa: BLE001 - prewarm is best-effort; bridge must still start
        _LOG.warning("could not prewarm WoRWS GATT cache: %s", err)
        return False
    finally:
        if started_discovery:
            try:
                adapter_iface.StopDiscovery()
            except dbus.exceptions.DBusException:
                pass


class WoRwsAdvertisementMonitor:
    """Log connection state and optional advertisements on the bridge's adapter only."""

    def __init__(self, adapter: str, remote_address: str, scan_enabled: bool = False) -> None:
        self.adapter = adapter
        self.remote_address = remote_address.upper()
        self.scan_enabled = scan_enabled
        self._addresses: dict[str, str] = {}
        self._bus = None

    @staticmethod
    def _data_map(value) -> dict[str, str]:
        if not value:
            return {}
        return {str(key): _dbus_bytes(data) for key, data in dict(value).items()}

    def _log(self, path: str, changed) -> None:
        if not path.startswith(f"/org/bluez/{self.adapter}/"):
            return
        values = dict(changed)
        address = str(values.get("Address") or self._addresses.get(path, "")).upper()
        if address:
            self._addresses[path] = address
        if "Connected" in values or "ServicesResolved" in values:
            _LOG.info(
                "BlueZ peer state address=%s connected=%s services_resolved=%s",
                address or "unknown",
                bool(values["Connected"]) if "Connected" in values else "unchanged",
                bool(values["ServicesResolved"]) if "ServicesResolved" in values else "unchanged",
            )
        if address != self.remote_address:
            return
        interesting = {
            "rssi": int(values["RSSI"]) if "RSSI" in values else None,
            "name": str(values.get("Name") or values.get("Alias") or ""),
            "manufacturer": self._data_map(values.get("ManufacturerData")),
            "service_data": self._data_map(values.get("ServiceData")),
            "uuids": [str(item) for item in values.get("UUIDs", [])],
        }
        if any(value not in (None, "", {}, []) for value in interesting.values()):
            _LOG.info("WORWS advertisement changed: %s", json.dumps(interesting, sort_keys=True))

    def _properties_changed(self, interface, changed, _invalidated, path=None) -> None:
        if str(interface) == "org.bluez.Device1" and path:
            self._log(str(path), changed)

    def _interfaces_added(self, path, interfaces) -> None:
        device = dict(interfaces).get("org.bluez.Device1")
        if device:
            self._log(str(path), device)

    def start(self) -> None:
        try:
            import dbus
            from dbus.mainloop.glib import DBusGMainLoop

            DBusGMainLoop(set_as_default=True)
            self._bus = dbus.SystemBus()
            manager_obj = self._bus.get_object("org.bluez", "/")
            manager = dbus.Interface(manager_obj, "org.freedesktop.DBus.ObjectManager")
            managed = manager.GetManagedObjects()
            adapter_path = next(
                (
                    str(path)
                    for path, interfaces in managed.items()
                    if "org.bluez.Adapter1" in interfaces
                    and str(path).rsplit("/", 1)[-1] == self.adapter
                ),
                None,
            )
            if adapter_path is None:
                raise RuntimeError(f"BlueZ adapter {self.adapter!r} was not found on D-Bus")
            adapter_properties = dict(managed[adapter_path]["org.bluez.Adapter1"])
            if bool(adapter_properties.get("Discovering", False)):
                _LOG.error(
                    "adapter %s is actively used by another BlueZ scanner. The bridge can "
                    "advertise, but WoRWS connections may never reach its GATT server. In "
                    "Home Assistant, disable this adapter for Bluetooth scanning (Settings > "
                    "Connectivity > Bluetooth > Adapters) and leave a different adapter for "
                    "Home Assistant devices. diagnostic_scan=false only disables the add-on's "
                    "own scanner.",
                    self.adapter,
                )
            for path, interfaces in managed.items():
                device = dict(interfaces).get("org.bluez.Device1")
                if device and device.get("Address"):
                    self._addresses[str(path)] = str(device["Address"]).upper()

            self._bus.add_signal_receiver(
                self._properties_changed,
                dbus_interface="org.freedesktop.DBus.Properties",
                signal_name="PropertiesChanged",
                path_keyword="path",
            )
            self._bus.add_signal_receiver(
                self._interfaces_added,
                dbus_interface="org.freedesktop.DBus.ObjectManager",
                signal_name="InterfacesAdded",
            )
            if self.scan_enabled:
                adapter_obj = self._bus.get_object("org.bluez", adapter_path)
                adapter_iface = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
                adapter_iface.SetDiscoveryFilter(
                    {"Transport": dbus.String("le"), "DuplicateData": dbus.Boolean(True)}
                )
                try:
                    adapter_iface.StartDiscovery()
                except dbus.exceptions.DBusException as err:
                    if "InProgress" not in err.get_dbus_name():
                        raise
                _LOG.warning(
                    "diagnostic scan enabled on %s; disable it for reliable peripheral mode",
                    self.adapter,
                )
            else:
                _LOG.info(
                    "BlueZ connection monitor started on %s; active scanning is disabled",
                    self.adapter,
                )
        except Exception as err:  # noqa: BLE001
            _LOG.warning("could not start WoRWS advertisement monitor: %s", err)


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


async def _execute_remote_management(
    adapter: str, address: str, key: bytes, key_id: int, steps: list
) -> dict:
    """Run the WoRWS management session as a BLE central on the bridge's own controller.

    Home Assistant cannot drive this controller (the add-on owns it, and HA Bluetooth manages a
    different adapter), and the WoRWS remote only completes its get-random handshake on the
    controller it is bound to. So the integration hands us the plaintext step list and we execute
    it here, on the adapter where the handshake works, while our peripheral advertisement is paused.
    """
    from bleak import BleakClient, BleakScanner

    # WoRWS pushes periodic status notifications that are not command replies. Their first byte
    # is not fixed — 3C, 4A, 4C, 4D, 4E and 4F have all been captured — so an allowlist of it
    # goes stale and the next status packet is taken as a reply, shifting every later response
    # in the sequence by one. Every captured status record is sixteen bytes whose second byte is
    # 2D or 30, and no real reply code collides with that.
    command_codes = {0x00, 0x01, 0x02, 0x04, 0x05, 0x10, 0x11}

    def _is_status(plaintext: bytes) -> bool:
        if len(plaintext) != 16 or plaintext[1] not in (0x2D, 0x30):
            return False
        return plaintext[0] not in command_codes
    queue: "asyncio.Queue[bytes]" = asyncio.Queue()

    def _on_notify(_char, data) -> None:  # noqa: ANN001
        raw = bytes(data)
        _LOG.info("management notify rx: %s", raw.hex())
        queue.put_nowait(raw)

    async def _await(match, timeout: float) -> bytes:
        """Wait for the first notification `match(raw)` accepts, within `timeout`."""
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            raw = await asyncio.wait_for(queue.get(), timeout=remaining)
            if match(raw):
                return raw

    # Establish a fresh connection, retrying: right after a prior management window the remote is
    # briefly reconnecting to the just re-advertised fake device, so the first connect can time
    # out. Clear the cached Device1 and retry a few times before giving up.
    stage = "connect"
    client_obj = None
    last_err: Exception | None = None
    for attempt in range(1, 4):
        _clear_bluez_device(adapter, address)
        await asyncio.sleep(1.0 if attempt == 1 else 2.0)
        try:
            device = await BleakScanner.find_device_by_address(
                address, timeout=20.0, adapter=adapter
            )
        except TypeError:
            device = await BleakScanner.find_device_by_address(address, timeout=20.0)
        if device is None:
            last_err = RuntimeError(f"WoRWS {address} not found on {adapter}")
            continue
        try:
            candidate = BleakClient(device, adapter=adapter)
        except TypeError:
            candidate = BleakClient(device)
        try:
            await candidate.connect()
            # BlueZ sometimes returns a cached, incomplete GATT table in which the SwitchBot
            # service is absent. The handshake cannot run on such a connection, so treat it
            # as a failed attempt: the loop clears the cached device and rediscovers.
            if (
                candidate.services.get_characteristic(CHAR_NOTIFY) is None
                or candidate.services.get_characteristic(CHAR_WRITE) is None
            ):
                raise RuntimeError(
                    "GATT discovery returned an incomplete service table; the SwitchBot "
                    "characteristics are missing"
                )
            client_obj = candidate
            break
        except Exception as err:  # noqa: BLE001 - retry a transient connect failure
            last_err = err
            _LOG.info("management: connect attempt %d/3 failed: %s", attempt, err)
            try:
                await candidate.disconnect()
            except Exception:  # noqa: BLE001
                pass
    if client_obj is None:
        # Never connected: no command was written, so the caller may safely retry (e.g. after a
        # credential refresh) without risking a half-applied mutation.
        return {
            "ok": False,
            "failed_stage": "connect",
            "error": str(last_err or f"could not connect to WoRWS {address}"),
            "iv": "",
            "responses": [],
        }

    responses: list[str] = []
    iv = b""
    client = client_obj
    try:
        try:
            chars = [c.uuid for s in client.services for c in s.characteristics]
            _LOG.info("management: connected, characteristics=%s", chars)
        except Exception:  # noqa: BLE001 - diagnostics only
            pass
        stage = "handshake"
        await client.start_notify(CHAR_NOTIFY, _on_notify)
        _LOG.info("management: notify subscribed on %s", CHAR_NOTIFY)
        # WoRWS gates its protocol on a negotiated ATT MTU (the device drops/garbles larger
        # frames and answers 02 to get-random until the MTU is exchanged). BlueZ does not always
        # auto-acquire it, so force it like the hardware-proven bind script does.
        backend = getattr(client, "_backend", None)
        acquire_mtu = getattr(backend, "_acquire_mtu", None)
        if callable(acquire_mtu):
            try:
                await acquire_mtu()
            except Exception as err:  # noqa: BLE001 - diagnostics only
                _LOG.info("management: MTU acquire failed: %s", err)
        _LOG.info("management: mtu=%s", getattr(client, "mtu_size", "?"))
        # get-random handshake: 57 00 00 00 0F 21 03 <keyId> -> 01 00 00 00 <16B IV>.
        # The hardware-proven bind script writes this WITHOUT response; a with-response write makes
        # the remote answer 02 00 00 00... (rejection) instead of the random.
        await client.write_gatt_char(
            CHAR_WRITE, bytes([0x57, 0, 0, 0, 0x0F, 0x21, 0x03, key_id]), response=False
        )
        _LOG.info("management: wrote get-random (keyId=%02x), awaiting IV", key_id)
        raw = await _await(
            lambda r: len(r) >= 20 and r[:4] == b"\x01\x00\x00\x00", timeout=35.0
        )
        iv = raw[4:20]
        _LOG.info("management: handshake IV=%s", iv.hex())

        # Effective write-without-response payload, matching the standalone script's transport.
        write_char = client.services.get_characteristic(CHAR_WRITE)
        reported_wnr = int(getattr(write_char, "max_write_without_response_size", 20) or 20)
        mtu = int(getattr(client, "mtu_size", 23) or 23)
        wnr = max(20, reported_wnr, (mtu - 3) if mtu > 23 else 20)

        async def _write_frame(frame: bytes) -> None:
            if len(frame) <= wnr:
                await client.write_gatt_char(CHAR_WRITE, frame, response=False)
            elif len(frame) <= 512 and "write" in (getattr(write_char, "properties", []) or []):
                await client.write_gatt_char(CHAR_WRITE, frame, response=True)
            else:
                for off in range(0, len(frame), wnr):
                    await client.write_gatt_char(
                        CHAR_WRITE, frame[off:off + wnr], response=False
                    )
                    if off + wnr < len(frame):
                        await asyncio.sleep(0.05)

        stage = "command"
        for step in steps:
            kind = str(step.get("kind", ""))
            timeout = float(step.get("timeout", 20.0))
            if kind == "query":
                sub = int(step["subcmd"]) & 0xFF
                await client.write_gatt_char(
                    CHAR_WRITE, bytes([0x57, 0, 0, 0, 0x0F, 0x63, sub]), response=True
                )
                # 0F63 reads reply with the unencrypted 01 00 00 00 ... envelope.
                raw = await _await(
                    lambda r: len(r) >= 8 and r[:4] == b"\x01\x00\x00\x00", timeout=timeout
                )
                responses.append(raw.hex())
            elif kind == "command":
                plaintext = bytes.fromhex(str(step["plaintext"]))
                _LOG.info("management: command step plaintext=%s", plaintext.hex())
                frame = bytes([0x57, key_id, iv[0], iv[1]]) + aes_ctr(key, iv, plaintext)
                await _write_frame(frame)

                def _decrypt(r: bytes) -> bytes:
                    if len(r) == 4 and r[1] == key_id:
                        return r[:1]
                    if len(r) >= 4 and r[1] == key_id:
                        return aes_ctr(key, iv, r[4:])
                    return aes_ctr(key, iv, r)

                raw = await _await(
                    lambda r: bool(_decrypt(r)) and not _is_status(_decrypt(r)),
                    timeout=timeout,
                )
                decoded = _decrypt(raw)
                responses.append(decoded.hex())
                accepted = step.get("accepted_codes")
                if accepted is not None and decoded[0] not in accepted:
                    raise RuntimeError(
                        f"management step {len(responses)} rejected: response={decoded.hex()}"
                    )
            else:
                raise RuntimeError(f"unknown management step {kind!r}")
        try:
            await client.stop_notify(CHAR_NOTIFY)
        except Exception:  # noqa: BLE001 - disconnect will clean up anyway
            pass
        return {"ok": True, "iv": iv.hex(), "responses": responses, "strict_accepted_codes": True}
    except Exception as err:  # noqa: BLE001 - report the failing stage for safe retry decisions
        _LOG.exception("management failed at stage=%s", stage)
        return {
            "ok": False,
            "failed_stage": stage,
            "error": str(err),
            "iv": iv.hex() if iv else "",
            "responses": responses,
        }
    finally:
        try:
            await client_obj.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _clear_bluez_device(adapter: str, address: str) -> None:
    """Drop any cached/connected Device1 for the remote so bleak makes a fresh, live connection.

    The bridge prewarms + trusts the remote and keeps a connection monitor, which leaves BlueZ a
    cached GATT. bleak then reports "connected" off that cache and writes get-random before the
    real LE link is up, so the device never answers (observed: write -> stale 02 -> real connect
    6 s later -> timeout). Removing the device forces a clean connect + service discovery.
    """
    try:
        import dbus

        bus = dbus.SystemBus()
        adapter_path = f"/org/bluez/{adapter}"
        adapter_iface = dbus.Interface(
            bus.get_object("org.bluez", adapter_path), "org.bluez.Adapter1"
        )
        manager = dbus.Interface(
            bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager"
        )
        wanted = address.upper()
        for path, interfaces in manager.GetManagedObjects().items():
            props = dict(interfaces).get("org.bluez.Device1")
            if (
                props
                and str(path).startswith(adapter_path + "/")
                and str(props.get("Address", "")).upper() == wanted
            ):
                if props.get("Connected"):
                    try:
                        dbus.Interface(
                            bus.get_object("org.bluez", path), "org.bluez.Device1"
                        ).Disconnect()
                    except Exception:  # noqa: BLE001
                        pass
                adapter_iface.RemoveDevice(path)
                _LOG.info("management: cleared cached BlueZ device %s", wanted)
                return
    except Exception as err:  # noqa: BLE001 - best effort; a fresh scan may still succeed
        _LOG.info("management: could not clear cached device: %s", err)


def run_remote_management(
    adapter: str, address: str, key_hex: str, key_id: int, steps: list
) -> dict:
    """Blocking wrapper: run one management session and return {iv, responses}."""
    key = bytes.fromhex(key_hex)
    if len(key) != 16:
        raise ValueError("management key must be 16 bytes")
    return asyncio.run(
        _execute_remote_management(adapter, address.upper(), key, int(key_id) & 0xFF, steps)
    )

# A native WoStrip/WoFloorLamp remote sends the original device command (opcode 0F 49 01 ..)
# directly on press. These byte strings are recovered from StripKeyHandler in the app bundle and
# the direct plaintext transport was confirmed by a live WoRWS -> bridge ATT Write Command.
LIGHT_CMDS = [
    ("0f490101", "ON"),
    ("0f490102", "OFF"),
    ("0f49014400", "UP"),      # brighter
    ("0f49014401", "DOWN"),    # darker
    ("0f49014501", "LEFT"),    # temp-
    ("0f49014500", "RIGHT"),   # temp+
    ("0f49011264ffffff", "A"),
    ("0f49011264d2f0ff", "B"),
    ("0f49011264fff0d2", "C"),
]

# Profile coordinates for the already recovered WoStrip/WoFloorLamp page.  These let remotes
# installed with metadata v1 gain stable button IDs without another recreation.  Unknown/new
# profiles use the explicit coordinates carried by metadata v2 instead.
LIGHT_KEY_METADATA = {
    "0f490101": (0, 4, 5),
    "0f490102": (0, 5, 6),
    "0f49014400": (0, 8, 300),
    "0f49014401": (0, 9, 301),
    "0f49014501": (0, 6, 303),
    "0f49014500": (0, 7, 302),
    "0f49011264ffffff": (0, 0, 321),
    "0f49011264d2f0ff": (0, 1, 323),
    "0f49011264fff0d2": (0, 2, 322),
}

# Metadata appended by the Home Assistant integration to commands stored in a native page.
# WoRWS sends the command bytes verbatim, so this identifies the logical on-screen remote even
# when several native remotes all point to this bridge adapter's physical BLE address.
BRIDGE_TAG_MAGIC = bytes.fromhex("f09d")
BRIDGE_TAG_MAGIC_V2 = bytes.fromhex("f09e")
BRIDGE_EVENT_MAGIC_V3 = bytes.fromhex("57f003")

NATIVE_PROFILE_NAMES = {
    1: "PLUG", 2: "CURTAIN", 3: "BLIND_TILT", 4: "CEILING", 5: "BULB",
    6: "STRIP", 7: "CANDLE", 8: "BOT", 9: "FAN", 10: "ROLLER_SHADE",
    11: "AIR_PURIFIER", 12: "HUMIDIFIER", 13: "LOCK", 14: "SWITCH",
    15: "GARAGE_DOOR", 16: "TRV", 0xFE: "CUSTOM",
}

BUTTON_FUNCTION_NAMES = {
    5: "ON", 6: "OFF", 11: "PRESS", 22: "PAUSE", 60: "TEMP_UP", 61: "TEMP_DOWN",
    100: "MORE", 117: "AUTO", 119: "MODE", 120: "NATURAL", 121: "SLEEP",
    122: "BABY", 123: "VERTICAL_SWING", 124: "HORIZONTAL_SWING", 125: "LIGHT_MODE",
    126: "GEAR", 127: "PET", 128: "HUMIDIFY", 129: "LEVEL_3", 130: "LEVEL_2",
    131: "LEVEL_1", 132: "MUTE", 133: "LIGHT_ON", 134: "LIGHT_DIM",
    135: "LIGHT_OFF", 136: "VERTICAL_30", 137: "VERTICAL_60", 138: "VERTICAL_90",
    139: "VERTICAL_OFF", 140: "HORIZONTAL_30", 141: "HORIZONTAL_60",
    142: "HORIZONTAL_90", 143: "HORIZONTAL_OFF", 144: "SPEED_1", 145: "SPEED_2",
    146: "SPEED_3", 147: "SPEED_4", 148: "SPEED_5", 149: "SPEED_6",
    150: "SPEED_7", 151: "SPEED_8", 152: "SPEED_9", 300: "BRIGHTER",
    301: "DARKER", 302: "WARMER", 303: "COOLER", 311: "NIGHT", 312: "DAY",
    313: "MIDNIGHT", 314: "SLEEP_LIGHT", 315: "READ", 316: "RELAX", 317: "EAT",
    318: "FLASH", 320: "WHITE_MENU", 321: "WHITE", 322: "WARM_WHITE",
    323: "COLD_WHITE", 330: "COLOR_MENU",
    **{value: f"COLOR_{value - 330}" for value in range(331, 346)},
}

ALL_BUTTON_TYPES = list(dict.fromkeys(
    [name for _, name in LIGHT_CMDS]
    + list(BUTTON_FUNCTION_NAMES.values())
    + ["OPEN", "CLOSE", "UNLOCK", "LOCK", "POSITION", "UNKNOWN"]
))


def decode_button(
    plain_hex: str, button_function: int | None = None, device_type: str | None = None
) -> str:
    if button_function is not None:
        if button_function in (5, 6):
            if device_type in {"CURTAIN", "ROLLER_SHADE", "GARAGE_DOOR"}:
                return "OPEN" if button_function == 5 else "CLOSE"
            if device_type == "LOCK":
                return "UNLOCK" if button_function == 5 else "LOCK"
        if 1300 <= button_function < 1800:
            return "POSITION"
        return BUTTON_FUNCTION_NAMES.get(button_function, f"KEY_{button_function}")
    for prefix, name in LIGHT_CMDS:
        if prefix in plain_hex:
            return name
    return "UNKNOWN"


def decode_event_metadata(raw: bytes) -> dict[str, object]:
    """Decode source/key metadata without assuming one device family's button map."""
    if len(raw) >= 13 and raw[:3] == BRIDGE_EVENT_MAGIC_V3:
        profile_id = raw[3]
        key_fun = int.from_bytes(raw[11:13], "big")
        return {
            "device_type": NATIVE_PROFILE_NAMES.get(profile_id, f"PROFILE_{profile_id}"),
            "profile_id": profile_id,
            "remote_id": raw[4:8].hex(),
            "remote_slot": raw[8],
            "button_page": raw[9],
            "button_index": raw[10],
            "button_function": key_fun,
            "button_id": f"p{raw[9]}_k{raw[10]}",
            "command": raw.hex(),
            "metadata_version": 3,
        }
    if len(raw) >= 11 and raw[-11:-9] == BRIDGE_TAG_MAGIC_V2:
        return {
            "remote_id": raw[-9:-5].hex(),
            "remote_slot": raw[-5],
            "button_page": raw[-4],
            "button_index": raw[-3],
            "button_function": int.from_bytes(raw[-2:], "big"),
            "button_id": f"p{raw[-4]}_k{raw[-3]}",
            "command": raw[:-11].hex(),
            "metadata_version": 2,
        }
    if len(raw) >= 7 and raw[-7:-5] == BRIDGE_TAG_MAGIC:
        metadata: dict[str, object] = {
            "remote_id": raw[-5:-1].hex(),
            "remote_slot": raw[-1],
            "command": raw[:-7].hex(),
            "metadata_version": 1,
        }
        command = str(metadata["command"])
        for prefix, (page, key_index, key_fun) in LIGHT_KEY_METADATA.items():
            if prefix in command:
                metadata.update({
                    "button_page": page,
                    "button_index": key_index,
                    "button_function": key_fun,
                    "button_id": f"p{page}_k{key_index}",
                })
                break
        return metadata
    return {"command": raw.hex(), "metadata_version": 0}


def decode_event_source(raw: bytes) -> tuple[str | None, int | None]:
    """Return stable source fields for the existing device callback contract."""
    metadata = decode_event_metadata(raw)
    remote_id = metadata.get("remote_id")
    remote_slot = metadata.get("remote_slot")
    return (
        str(remote_id) if remote_id is not None else None,
        int(remote_slot) if remote_slot is not None else None,
    )


def publish_with_retry(
    periph,
    attempts: int = 10,
    delay_seconds: int = 3,
    raw_advertiser: RawMgmtAdvertiser | None = None,
    raw_att_server=None,
) -> None:
    """Register GATT then raw advertising, with a known-good D-Bus fallback."""
    import dbus
    from gi.repository import GLib

    if raw_att_server is not None and raw_att_server.listener is not None:
        try:
            if raw_advertiser is None:
                raise RuntimeError("raw ATT requires raw advertising")
            raw_advertiser.register()
            _LOG.info("direct ATT transport active; BlueZ D-Bus GATT is bypassed")
            periph.mainloop.run()
            return
        except (OSError, TimeoutError, RuntimeError) as err:
            _LOG.warning(
                "direct ATT startup failed: %s; using BlueZ GATT fallback", err
            )
            raw_att_server.close()

    for service in periph.services:
        periph.app.add_managed_object(service)
    for characteristic in periph.characteristics:
        periph.app.add_managed_object(characteristic)
    for descriptor in periph.descriptors:
        periph.app.add_managed_object(descriptor)
    periph._create_advertisement()  # Bluezero has no public equivalent.
    if not periph.dongle.powered:
        periph.dongle.powered = True

    state = {
        "application_attempt": 0,
        "application_ready": False,
        "advert_attempt": 0,
        "advert_started": False,
    }

    def register_advertisement() -> bool:
        if state["advert_started"]:
            return False
        state["advert_started"] = True
        state["advert_attempt"] += 1
        attempt = state["advert_attempt"]
        _LOG.info("registering advertisement (attempt %s/%s)", attempt, attempts)
        periph.ad_manager.advert_mngr_methods.RegisterAdvertisement(
            periph.advert.path,
            dbus.Dictionary({}, signature="sv"),
            reply_handler=lambda: _LOG.info("Advertisement registered"),
            error_handler=lambda error: advertisement_failed(error, attempt),
        )
        return False

    def advertisement_failed(error, attempt: int) -> None:
        state["advert_started"] = False
        if attempt >= attempts:
            _LOG.error(
                "advertisement registration failed after %s attempts: %s",
                attempts,
                error,
            )
            return
        _LOG.warning(
            "advertisement registration attempt %s failed: %s; retrying in %ss",
            attempt,
            error,
            delay_seconds,
        )
        GLib.timeout_add_seconds(delay_seconds, register_advertisement)

    def application_registered() -> None:
        if state["application_ready"]:
            return
        state["application_ready"] = True
        _LOG.info("GATT application registered")
        if raw_advertiser is not None:
            try:
                raw_advertiser.register()
                return
            except (OSError, TimeoutError, RuntimeError) as err:
                _LOG.warning(
                    "raw MGMT advertisement failed: %s; falling back to the "
                    "compatible D-Bus advertisement",
                    err,
                )
        register_advertisement()

    def register_application() -> bool:
        if state["application_ready"]:
            return False
        state["application_attempt"] += 1
        attempt = state["application_attempt"]
        _LOG.info("registering GATT application (attempt %s/%s)", attempt, attempts)
        periph.srv_mng.manager_methods.RegisterApplication(
            periph.app.get_path(),
            dbus.Dictionary({}, signature="sv"),
            reply_handler=application_registered,
            error_handler=lambda error: application_failed(error, attempt),
            timeout=15,
        )
        return False

    def application_failed(error, attempt: int) -> None:
        if state["application_ready"]:
            return
        error_name = getattr(error, "get_dbus_name", lambda: "")()
        if "AlreadyExists" in error_name or "Already Exists" in str(error):
            _LOG.warning("GATT application already exists after a delayed reply; continuing")
            application_registered()
            return
        if attempt >= attempts:
            _LOG.error(
                "GATT application registration failed after %s attempts: %s",
                attempts,
                error,
            )
            return
        _LOG.warning(
            "GATT application registration attempt %s failed: %s; retrying in %ss",
            attempt,
            error,
            delay_seconds,
        )
        GLib.timeout_add_seconds(delay_seconds, register_application)

    register_application()
    periph.mainloop.run()


def add_bridge_characteristics(periph, device) -> None:
    """Register the characteristics in the order used by the native SwitchBot service."""
    periph.add_characteristic(
        srv_id=1,
        chr_id=1,
        uuid=CHAR_WRITE,
        value=[],
        notifying=False,
        flags=["write", "write-without-response"],
        write_callback=lambda value, options: device.on_write(bytes(value)),
    )
    periph.add_characteristic(
        srv_id=1,
        chr_id=2,
        uuid=CHAR_NOTIFY,
        value=[],
        notifying=False,
        flags=["notify"],
        notify_callback=lambda notifying, char: _LOG.info("notify sub=%s", notifying),
    )


class SwitchBotDevice:
    """Device-side protocol: get-random handshake + AES-CTR decrypt of the remote's commands."""

    def __init__(self, key: bytes, notify, on_button) -> None:
        self._key = key
        self._notify = notify          # callable(bytes) -> notify on cba20003
        self._on_button = on_button     # callable(label, plain_hex, remote_id, remote_slot)
        self._iv: bytes | None = None
        self._key_id = 0x95
        self._last_command: bytes | None = None
        self._last_command_at = 0.0

    def _is_immediate_retry(self, command: bytes) -> bool:
        """Recognize the firmware retry caused by a late/lost application ACK."""
        now = time.monotonic()
        repeated = self._last_command == command and now - self._last_command_at < 0.25
        self._last_command = bytes(command)
        self._last_command_at = now
        return repeated

    def on_write(self, raw: bytes) -> None:
        _LOG.info("REMOTE wrote: %s", raw.hex())
        # Native device pages carry their target's command verbatim. Unlike phone -> WoRWS control
        # traffic, the observed WoStrip press is not wrapped in the 0x95 AES session protocol.
        if len(raw) >= 3 and (raw[:2] == b"\x57\x0f" or raw[:3] == BRIDGE_EVENT_MAGIC_V3):
            ph = raw.hex()
            metadata = decode_event_metadata(raw)
            key_fun = metadata.get("button_function")
            label = decode_button(
                str(metadata["command"]), int(key_fun) if key_fun is not None else None,
                str(metadata.get("device_type", "")),
            )
            remote_id, remote_slot = decode_event_source(raw)
            _LOG.info(">>> BUTTON: %s (native plaintext command)", label)
            # Native WoStrip writes are application transactions, even though the transport uses
            # an ATT Write Command and therefore has no ATT-level response.  The real target sends
            # a one-byte success result on cba20003.  WoRWS keeps the queued key command and retries
            # the connection (up to five times in firmware) until it receives this notification.
            # The app's common response parser accepts 0x01 as success for 57 0F 49 commands.
            if raw[:3] in (b"\x57\x0f\x49", BRIDGE_EVENT_MAGIC_V3):
                self._notify(b"\x01")
                _LOG.info("native command ack -> 01")
            # ACK is latency-sensitive; MQTT discovery/publication is not. Publish only after
            # the ACK is on the ATT socket and absorb the firmware's immediate retransmission.
            if self._is_immediate_retry(raw):
                _LOG.info("duplicate native command acknowledged without a second HA event")
            else:
                self._on_button(label, ph, remote_id, remote_slot)
            return
        # get-random handshake: 57 00 00 00 0F 21 03 <keyId> -> reply 01 00 00 00 <16B IV>.
        if (len(raw) >= 8 and raw[0] == 0x57 and raw[1:5] == b"\x00\x00\x00\x0f"
                and raw[5:7] == b"\x21\x03"):
            self._key_id = raw[7] if len(raw) > 7 else 0x95
            self._iv = os.urandom(16)
            _LOG.info("handshake get-random -> IV=%s", self._iv.hex())
            self._notify(bytes([0x01, 0x00, 0x00, 0x00]) + self._iv)
            return
        # Encrypted command: 57 <keyId> <nonce0> <nonce1> <ciphertext>.
        if len(raw) >= 4 and raw[0] == 0x57 and self._iv is not None:
            if raw[1] != self._key_id:
                _LOG.warning("encrypted frame uses unexpected keyId=%02x (expected %02x)",
                             raw[1], self._key_id)
            plain = aes_ctr(self._key, self._iv, raw[4:])
            ph = plain.hex()
            _LOG.info("decrypted command: %s", ph)
            # The remote relays the stored key command with its leading 0x57 magic consumed as the
            # frame magic, so the decrypted payload lacks it (e.g. f00306... instead of 57f00306...).
            # Restore it so the v3 bridge event decodes with its remote_id/slot/button, exactly like
            # an unencrypted native write; otherwise every press is logged as UNKNOWN/legacy.
            full = b"\x57" + plain
            metadata = decode_event_metadata(full)
            key_fun = metadata.get("button_function")
            label = decode_button(
                str(metadata["command"]),
                int(key_fun) if key_fun is not None else None,
                str(metadata.get("device_type", "")),
            )
            remote_id, remote_slot = decode_event_source(full)
            _LOG.info(
                ">>> BUTTON: %s remote_id=%s slot=%s", label, remote_id, remote_slot
            )
            # ACK before MQTT: first-use discovery can take about 100 ms, long enough for WoRWS
            # to retransmit the command.
            ack = aes_ctr(self._key, self._iv, bytes([0x01]))
            self._notify(bytes([0x01, self._key_id, self._iv[0], self._iv[1]]) + ack)
            # Publish unknown commands too: the first live press is protocol evidence and must
            # not disappear merely because the local map does not know it yet.
            if self._is_immediate_retry(full):
                _LOG.info("duplicate encrypted command acknowledged without a second HA event")
            else:
                self._on_button(label, full.hex(), remote_id, remote_slot)
            return
        _LOG.info("unhandled write (no IV yet / bad frame): %s", raw.hex())


def _uuid128_le(value: str) -> bytes:
    """Encode a canonical UUID in the little-endian form used by ATT."""
    return bytes.fromhex(value.replace("-", ""))[::-1]


class FastAttProtocol:
    """Minimal in-process ATT database for the latency-sensitive WoRWS client."""

    SERVICE_HANDLE = 0x0001
    # WoRWS needs the normal write -> notify -> CCCD ordering: a notification transmitted before
    # the client has enabled that CCCD is visible in an HCI trace but is not delivered to its
    # command-completion state machine.  A no-access, unknown-UUID declaration at the group end is
    # returned only as a discovery sentinel.  It makes the first characteristic response end on
    # SERVICE_END, avoiding the otherwise fatal continuation request while leaving the real notify
    # value and CCCD adjacent.  Put the no-access discovery sentinel at the final ATT handle and
    # make it the service boundary.  WoRWS has a roughly two-second discovery budget; an earlier
    # group end makes it issue a redundant second primary-service search, while an ordinary last
    # declaration makes it issue a characteristic continuation.  A final-handle sentinel closes
    # both searches (and the later Find Information walk) in their first response.
    SERVICE_END = 0xFFFF
    WRITE_DECL = 0x0002
    WRITE_VALUE = 0x0003
    NOTIFY_DECL = 0x0004
    NOTIFY_VALUE = 0x0005
    CCCD = 0x0006
    SENTINEL_DECL = 0xFFFE
    SENTINEL_VALUE = 0xFFFF
    SENTINEL_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

    def __init__(self, on_write) -> None:
        self.on_write = on_write
        self.notify_enabled = False
        self.peer_mtu = 23
        self.sender = None
        self.session_stages: list[str] = []
        self.session_writes = 0
        # Monotonic timestamps for the press transaction: connect -> subscribe -> device-write
        # -> notify-ack.  WoRWS has a roughly two-second discovery budget, so these latencies are
        # the objective measure of "fast and stable"; they are logged in the session summary.
        self.session_start = 0.0
        self.subscribe_time: float | None = None
        self.device_write_time: float | None = None
        self.ack_time: float | None = None
        self.last_device_write_time: float | None = None
        self.last_notification: bytes | None = None
        self.last_notify_time: float | None = None
        self.keepalive_count = 0

    def begin_session(self) -> None:
        """Reset the bounded per-connection trace used in normal INFO logs."""
        self.session_stages = []
        self.session_writes = 0
        self.session_start = time.monotonic()
        self.subscribe_time = None
        self.device_write_time = None
        self.ack_time = None
        self.last_device_write_time = None
        self.last_notification = None
        self.last_notify_time = None
        self.keepalive_count = 0

    def _stage(self, value: str) -> None:
        # Consecutive duplicates add no diagnostic value and can make retry logs noisy.
        if not self.session_stages or self.session_stages[-1] != value:
            self.session_stages.append(value)

    def _ms_since_start(self, when: float | None) -> str:
        if when is None or not self.session_start:
            return "-"
        return f"{(when - self.session_start) * 1000:.0f}ms"

    def session_summary(self) -> str:
        path = ">".join(self.session_stages) if self.session_stages else "no-att-request"
        write_to_ack = "-"
        if self.device_write_time is not None and self.ack_time is not None:
            write_to_ack = f"{(self.ack_time - self.device_write_time) * 1000:.0f}ms"
        return (
            f"path={path} mtu={self.peer_mtu} subscribed={self.notify_enabled} "
            f"device_writes={self.session_writes} "
            f"keepalives={self.keepalive_count} "
            f"t_subscribe={self._ms_since_start(self.subscribe_time)} "
            f"t_write={self._ms_since_start(self.device_write_time)} "
            f"t_ack={self._ms_since_start(self.ack_time)} write_to_ack={write_to_ack}"
        )

    @staticmethod
    def _error(request: int, handle: int, code: int = 0x0A) -> bytes:
        return bytes([0x01, request]) + struct.pack("<H", handle) + bytes([code])

    def handle(self, pdu: bytes) -> bytes | None:
        if not pdu:
            return None
        opcode = pdu[0]
        if opcode == 0x02 and len(pdu) >= 3:  # Exchange MTU Request
            self._stage("mtu-request")
            return b"\x03" + struct.pack("<H", 512)
        if opcode == 0x03 and len(pdu) >= 3:  # Exchange MTU Response
            self._stage("mtu-response")
            self.peer_mtu = max(23, min(512, struct.unpack_from("<H", pdu, 1)[0]))
            _LOG.debug("raw ATT negotiated MTU=%s", self.peer_mtu)
            return None
        if opcode == 0x06 and len(pdu) >= 7:  # Find By Type Value Request
            self._stage("service-discovery")
            start, end, attribute_type = struct.unpack_from("<HHH", pdu, 1)
            if (
                attribute_type == 0x2800
                and start <= self.SERVICE_HANDLE <= end
                and pdu[7:] == _uuid128_le(SVC)
            ):
                return b"\x07" + struct.pack(
                    "<HH", self.SERVICE_HANDLE, self.SERVICE_END
                )
            return self._error(opcode, start)
        if opcode == 0x08 and len(pdu) >= 7:  # Read By Type Request
            start, end = struct.unpack_from("<HH", pdu, 1)
            attribute_type = pdu[5:]
            if attribute_type == b"\x02\x28":
                self._stage("include-discovery")
            elif attribute_type == b"\x03\x28":
                self._stage("characteristic-discovery")
            else:
                self._stage("read-by-type")
            if attribute_type == b"\x03\x28":
                entries = []
                if start <= self.WRITE_DECL <= end:
                    entries.append(
                        struct.pack("<HBH", self.WRITE_DECL, 0x0C, self.WRITE_VALUE)
                        + _uuid128_le(CHAR_WRITE)
                    )
                if start <= self.NOTIFY_DECL <= end:
                    entries.append(
                        struct.pack("<HBH", self.NOTIFY_DECL, 0x10, self.NOTIFY_VALUE)
                        + _uuid128_le(CHAR_NOTIFY)
                    )
                if start <= self.SENTINEL_DECL <= end:
                    entries.append(
                        struct.pack("<HBH", self.SENTINEL_DECL, 0x00, self.SENTINEL_VALUE)
                        + _uuid128_le(self.SENTINEL_UUID)
                    )
                if entries:
                    return bytes([0x09, 21]) + b"".join(entries)
            return self._error(opcode, start)
        if opcode == 0x04 and len(pdu) >= 5:  # Find Information Request
            self._stage("descriptor-discovery")
            start, end = struct.unpack_from("<HH", pdu, 1)
            if start <= self.CCCD <= end:
                # Return every 16-bit attribute in monotonically increasing handle order. WoRWS
                # uses this broad query to locate the CCCD and accepts the sparse raw table.
                entries: list[tuple[int, int]] = []
                if start <= self.WRITE_DECL <= end:
                    entries.append((self.WRITE_DECL, 0x2803))
                if start <= self.NOTIFY_DECL <= end:
                    entries.append((self.NOTIFY_DECL, 0x2803))
                if start <= self.CCCD <= end:
                    entries.append((self.CCCD, 0x2902))
                if start <= self.SENTINEL_DECL <= end:
                    entries.append((self.SENTINEL_DECL, 0x2803))
                if start <= self.SENTINEL_VALUE <= end:
                    # Find Information cannot mix 16- and 128-bit UUID formats in one response.
                    # WoRWS only needs the CCCD type from this walk; expose the no-access
                    # sentinel value as a terminal 16-bit marker so it does not spend another
                    # connection event querying handle 0xFFFF separately.
                    entries.append((self.SENTINEL_VALUE, 0x2803))
                return b"\x05\x01" + b"".join(
                    struct.pack("<HH", handle, uuid)
                    for handle, uuid in sorted(entries)
                )
            return self._error(opcode, start)
        if opcode == 0x0A and len(pdu) >= 3:  # Read Request
            self._stage("read")
            handle = struct.unpack_from("<H", pdu, 1)[0]
            if handle == self.CCCD:
                return b"\x0b" + struct.pack("<H", int(self.notify_enabled))
            return self._error(opcode, handle, 0x02)
        if opcode in (0x12, 0x52) and len(pdu) >= 3:  # Write Request / Command
            handle = struct.unpack_from("<H", pdu, 1)[0]
            value = pdu[3:]
            if handle == self.CCCD:
                self._stage("cccd-write")
                self.notify_enabled = value[:2] == b"\x01\x00"
                if self.notify_enabled and self.subscribe_time is None:
                    self.subscribe_time = time.monotonic()
                _LOG.info("notify sub=%s (raw ATT)", self.notify_enabled)
            elif handle == self.WRITE_VALUE:
                self._stage("device-write")
                self.session_writes += 1
                now = time.monotonic()
                is_handshake = (
                    len(value) >= 7
                    and value[0] == 0x57
                    and value[1:5] == b"\x00\x00\x00\x0f"
                    and value[5:7] == b"\x21\x03"
                )
                is_native_command = (
                    len(value) >= 3
                    and (value[:2] == b"\x57\x0f" or value[:3] == BRIDGE_EVENT_MAGIC_V3)
                )
                is_encrypted_command = (
                    len(value) >= 4 and value[0] == 0x57 and not is_handshake
                )
                if is_native_command or is_encrypted_command:
                    # Do not arm keepalive from the get-random handshake used by diagnostics.
                    # It must begin only after an actual native button command.
                    self.last_device_write_time = now
                if self.device_write_time is None:
                    self.device_write_time = now
                self.on_write(value)
            elif opcode == 0x12:
                return self._error(opcode, handle, 0x01)
            return b"\x13" if opcode == 0x12 else None
        return self._error(opcode, 0x0000, 0x06)

    def notify(self, data: bytes) -> None:
        if self.sender is None:
            _LOG.warning("raw ATT notification dropped: no active WoRWS connection")
            return
        # A notification that WoRWS has not subscribed to is transmitted on-air but never reaches
        # its command-completion state machine, so the remote retries the whole press.  Logging it
        # makes that failure mode visible in the session summary instead of looking like success.
        if not self.notify_enabled:
            _LOG.warning("raw ATT notify sent before CCCD subscription: %s", data.hex())
        self.sender(b"\x1b" + struct.pack("<H", self.NOTIFY_VALUE) + data)
        self.last_notification = bytes(data)
        self.last_notify_time = time.monotonic()
        if self.ack_time is None:
            self.ack_time = self.last_notify_time
        _LOG.info("device -> raw ATT notify: %s", data.hex())

    def send_keepalive(
        self,
        interval: float = RAW_ATT_KEEPALIVE_INTERVAL,
        window: float = RAW_ATT_KEEPALIVE_WINDOW,
        now: float | None = None,
    ) -> bool:
        """Repeat the last valid ACK while WoRWS' bounded command window is active."""
        now = time.monotonic() if now is None else now
        if (
            interval <= 0
            or window <= 0
            or self.sender is None
            or not self.notify_enabled
            or self.last_device_write_time is None
            or self.last_notification is None
            or now - self.last_device_write_time > window
            or (self.last_notify_time is not None and now - self.last_notify_time < interval)
        ):
            return False
        self.sender(
            b"\x1b" + struct.pack("<H", self.NOTIFY_VALUE) + self.last_notification
        )
        self.last_notify_time = now
        self.keepalive_count += 1
        if self.keepalive_count == 1:
            _LOG.info(
                "native ACK keepalive active (interval=%.2fs window=%.1fs)",
                interval,
                window,
            )
        else:
            _LOG.debug("native ACK keepalive #%d", self.keepalive_count)
        return True


class RawAttServer:
    """Own the fixed ATT CID on one adapter and answer WoRWS discovery synchronously."""

    def __init__(
        self,
        address: str,
        protocol: FastAttProtocol,
        idle_timeout: float = RAW_ATT_IDLE_TIMEOUT,
        keepalive_interval: float = RAW_ATT_KEEPALIVE_INTERVAL,
        keepalive_window: float = RAW_ATT_KEEPALIVE_WINDOW,
    ) -> None:
        self.address = address
        self.protocol = protocol
        # A half-open link that the kernel never reports as closed would otherwise wedge this
        # single-connection server and starve every following press of its accept slot. The bounded
        # keepalive may intentionally keep a proven command connection warm; after its window ends,
        # idle eviction frees the slot normally.
        self.idle_timeout = idle_timeout
        self.keepalive_interval = keepalive_interval
        self.keepalive_window = keepalive_window
        self.listener: socket.socket | None = None
        self.connection: socket.socket | None = None

    def start(self) -> bool:
        af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
        btproto_l2cap = getattr(socket, "BTPROTO_L2CAP", 0)
        sock_type = socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0)
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.socket(af_bluetooth, sock_type, btproto_l2cap)
        if fd < 0:
            error = ctypes.get_errno()
            _LOG.warning("raw ATT socket unavailable: %s", os.strerror(error))
            return False
        address = bytes.fromhex(self.address.replace(":", ""))[::-1]
        sockaddr = struct.pack("=HH6sHBx", af_bluetooth, 0, address, 0x0004, 0x01)
        if libc.bind(fd, sockaddr, len(sockaddr)) < 0:
            error = ctypes.get_errno()
            os.close(fd)
            _LOG.warning(
                "raw ATT bind unavailable on %s: %s; using BlueZ GATT fallback",
                self.address,
                os.strerror(error),
            )
            return False
        listener = socket.socket(af_bluetooth, sock_type, btproto_l2cap, fileno=fd)
        listener.listen(4)
        self.listener = listener
        threading.Thread(target=self._accept_loop, name="raw-att", daemon=True).start()
        _LOG.info("raw ATT server listening on %s (CID 0x0004)", self.address)
        return True

    def _accept_loop(self) -> None:
        assert self.listener is not None
        while self.listener is not None:
            try:
                connection, peer = self.listener.accept()
                self.connection = connection
                self.protocol.begin_session()
                self.protocol.sender = connection.sendall
                _LOG.info("RAW ATT CONNECTED peer=%s", peer)
                # BlueZ used to initiate this exchange as its reverse GATT client. The direct
                # server must do it itself before returning the 44-byte two-characteristic list;
                # without negotiation WoRWS correctly drops anything larger than ATT_MTU 23.
                connection.sendall(b"\x02\x00\x02")
                _LOG.debug("RAW ATT TX: 020002 (Exchange MTU Request: 512)")
                last_peer_activity = time.monotonic()
                while True:
                    # A blocking recv here would hang the only accept thread forever on a
                    # half-open link, so select bounds the wait.  An empty ready list means the
                    # peer has been silent for idle_timeout: drop it so the next (retry or new)
                    # WoRWS connection waiting in the listen backlog is served immediately.
                    poll_timeout = self.idle_timeout
                    if self.keepalive_interval > 0:
                        poll_timeout = min(poll_timeout, self.keepalive_interval)
                    ready, _, _ = select.select([connection], [], [], poll_timeout)
                    if self.connection is not connection:
                        # A management window closed this connection; stop serving it.
                        break
                    if not ready:
                        now = time.monotonic()
                        if self.protocol.send_keepalive(
                            self.keepalive_interval, self.keepalive_window, now
                        ):
                            continue
                        if now - last_peer_activity < self.idle_timeout:
                            continue
                        _LOG.info(
                            "raw ATT peer idle >%.1fs; evicting to free the accept slot",
                            self.idle_timeout,
                        )
                        break
                    pdu = connection.recv(512)
                    if not pdu:
                        break
                    last_peer_activity = time.monotonic()
                    _LOG.debug("RAW ATT RX: %s", pdu.hex())
                    response = self.protocol.handle(pdu)
                    if response is not None:
                        connection.sendall(response)
                        _LOG.debug("RAW ATT TX: %s", response.hex())
            except OSError as err:
                if self.listener is None:
                    # Listener was closed on purpose (management window); stop the accept loop.
                    return
                # The remote resetting the link after an idle poll is routine churn, not an error.
                _LOG.debug("raw ATT connection ended: %s", err)
            finally:
                _LOG.info("raw ATT session summary: %s", self.protocol.session_summary())
                self.protocol.sender = None
                self.protocol.notify_enabled = False
                self.protocol.peer_mtu = 23
                if self.connection is not None:
                    self.connection.close()
                    self.connection = None

    def close(self) -> None:
        self.protocol.sender = None
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.listener is not None:
            self.listener.close()
            self.listener = None

    def disconnect_peer(self) -> None:
        """Drop only the active WoRWS link while keeping the ATT listener available."""
        connection = self.connection
        if connection is None:
            return
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            connection.close()
        except OSError:
            pass
        self.connection = None
        _LOG.info("active WoRWS bridge connection closed for management window")


class Mqtt:
    def __init__(self, topic: str, discovery: bool, remote_address: str = "") -> None:
        self._topic = topic
        self._discovery = discovery
        self._remote_address = remote_address.upper()
        self._published_remote_ids: set[str] = set()
        self._published_remote_buttons: set[tuple[str, str]] = set()
        self._client = None
        host = os.environ.get("MQTT_HOST")
        if not host:
            return
        import paho.mqtt.client as mqtt

        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        if os.environ.get("MQTT_USER"):
            self._client.username_pw_set(os.environ["MQTT_USER"], os.environ.get("MQTT_PASS", ""))
        # The loop thread reconnects automatically on an unexpected drop; keep the backoff short so
        # control is restored quickly after a broker blip (the subscription is re-armed in on_connect).
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._client.connect(host, int(os.environ.get("MQTT_PORT", "1883")), keepalive=60)
        self._client.loop_start()
        if discovery:
            self._publish_discovery()

    def set_control_handler(
        self, handler, *, adapter_name: str, adapter_address: str
    ) -> None:  # noqa: ANN001
        """Subscribe to integration requests that pause/resume peripheral mode."""
        if self._client is None:
            return

        bridge_identity = {
            "adapter": adapter_name,
            "adapter_address": adapter_address.upper(),
        }
        manage_lock = threading.Lock()
        management_results: dict[str, dict] = {}

        def _run_management(client, payload: dict) -> None:  # noqa: ANN001
            """Pause the peripheral, run the WoRWS management session, resume, report result."""
            request_id = str(payload.get("request_id", ""))
            result: dict = {"ok": False, "failed_stage": "bridge", "error": "not started"}
            paused = False
            # Serialize management: a retry or duplicate MQTT request must not start a second
            # pause/connect while the first is mid-flight (that closed the ATT listener, so the
            # second pause would fail and both BLE connections would fight for the controller).
            with manage_lock:
                if request_id and request_id in management_results:
                    client.publish(
                        "switchbot_urc/bridge/manage_result",
                        json.dumps({"request_id": request_id, **management_results[request_id], **bridge_identity}),
                        qos=1,
                    )
                    return
                try:
                    paused = bool(handler("pause"))
                    if not paused:
                        raise RuntimeError("could not pause peripheral before management")
                    time.sleep(0.5)
                    result = run_remote_management(
                        adapter_name,
                        str(payload["address"]),
                        str(payload["key"]),
                        int(payload["key_id"]),
                        list(payload.get("steps", [])),
                    )
                    if result.get("ok"):
                        _LOG.info(
                            "remote management ok: iv=%s responses=%s",
                            result.get("iv", ""),
                            result.get("responses", []),
                        )
                    else:
                        _LOG.warning(
                            "remote management failed at stage=%s: %s",
                            result.get("failed_stage", ""),
                            result.get("error", ""),
                        )
                except Exception as err:  # noqa: BLE001 - report management failure over MQTT
                    result = {"ok": False, "failed_stage": "bridge", "error": str(err)}
                    _LOG.exception("remote management bridge error")
                finally:
                    if paused:
                        try:
                            handler("resume")
                        except Exception:  # noqa: BLE001 - do not hide the management result
                            _LOG.exception("could not resume peripheral after management")
                    if request_id:
                        management_results[request_id] = result
                        if len(management_results) > 64:
                            management_results.pop(next(iter(management_results)))
            client.publish(
                "switchbot_urc/bridge/manage_result",
                json.dumps({"request_id": request_id, **result, **bridge_identity}),
                qos=1,
            )

        def _on_message(client, _userdata, message) -> None:  # noqa: ANN001
            topic = str(getattr(message, "topic", ""))
            try:
                payload = json.loads(message.payload)
            except Exception:  # noqa: BLE001
                _LOG.warning("ignored malformed bridge message on %s", topic)
                return
            if topic.endswith("/manage"):
                # Management can take tens of seconds (connect + handshake + commands); run it off
                # the paho network thread so keepalive/ping traffic keeps flowing meanwhile.
                threading.Thread(
                    target=_run_management, args=(client, payload), daemon=True
                ).start()
                return
            request_id = str(payload.get("request_id", ""))
            action = str(payload.get("action", ""))
            ok = False
            error = ""
            try:
                if action not in {"pause", "resume"}:
                    raise ValueError(f"unsupported bridge action: {action}")
                ok = bool(handler(action))
            except Exception as err:  # noqa: BLE001 - report control failure over MQTT
                error = str(err)
                _LOG.exception("native bridge control %s failed", action or "request")
            client.publish(
                "switchbot_urc/bridge/status",
                json.dumps(
                    {
                        "request_id": request_id,
                        "action": action,
                        "ok": ok,
                        "error": error,
                        **bridge_identity,
                    }
                ),
                qos=1,
            )

        def _register_control(client) -> None:  # noqa: ANN001
            """(Re)establish the control + management subscriptions and retained identity."""
            client.subscribe("switchbot_urc/bridge/control", qos=1)
            client.subscribe("switchbot_urc/bridge/manage", qos=1)
            client.publish(
                "switchbot_urc/bridge/info",
                json.dumps(bridge_identity),
                qos=1,
                retain=True,
            )

        def _on_connect(client, _userdata, _flags, _reason_code, _properties=None) -> None:  # noqa: ANN001
            # paho uses a clean session by default, so the broker drops every subscription on an
            # unexpected disconnect. Re-subscribe on every (re)connect; otherwise a broker blip
            # (e.g. restarting the Mosquitto add-on) silently kills control while publishing keeps
            # working, which looks exactly like "subscribed once, never answers a pause".
            _register_control(client)
            _LOG.info("subscribed to native bridge management control")

        self._client.on_message = _on_message
        self._client.on_connect = _on_connect
        # The initial CONNACK already fired before this handler was attached, so register now for
        # the current connection; _on_connect covers every later reconnect.
        _register_control(self._client)
        _LOG.info("subscribed to native bridge management control")

    def _publish_discovery(self) -> None:
        # Keep the event entity for dashboards/history and also publish native MQTT device
        # triggers so a button can be selected directly in Home Assistant's automation UI.
        cfg_topic = "homeassistant/event/switchbot_urc_button/config"
        button_types = ALL_BUTTON_TYPES
        device = {
            "identifiers": ["switchbot_urc_bridge"],
            "name": "SwitchBot URC Bridge",
            "manufacturer": "SwitchBot",
            "model": "WoRWS native bridge",
            "sw_version": "0.19.32",
        }
        payload = {
            "name": "SwitchBot URC Button",
            "state_topic": self._topic,
            "event_types": button_types,
            "unique_id": "switchbot_urc_button",
            "device": device,
        }
        self._client.publish(cfg_topic, json.dumps(payload), retain=True)

        # One unfiltered trigger is useful while reverse-engineering new buttons. Individual
        # triggers use the JSON button label, while trigger.payload_json still exposes raw bytes.
        any_trigger = {
            "automation_type": "trigger",
            "platform": "device_automation",
            "type": "button_short_press",
            "subtype": "any_button",
            "topic": self._topic,
            "device": device,
        }
        self._client.publish(
            "homeassistant/device_automation/switchbot_urc_bridge/any_button/config",
            json.dumps(any_trigger),
            retain=True,
        )
        for label in button_types:
            object_id = label.lower()
            trigger = {
                "automation_type": "trigger",
                "platform": "device_automation",
                "type": "button_short_press",
                "subtype": object_id,
                "topic": self._topic,
                "payload": label,
                "value_template": "{{ value_json.button }}",
                "device": device,
            }
            self._client.publish(
                f"homeassistant/device_automation/switchbot_urc_bridge/{object_id}/config",
                json.dumps(trigger),
                retain=True,
            )
        _LOG.info(
            "published HA discovery for the button event entity and %s device triggers",
            len(button_types) + 1,
        )

    def _publish_remote_discovery(self, remote_id: str) -> None:
        """Create a distinct HA device and button triggers for one logical WoRWS remote."""
        if not self._client or not self._discovery or remote_id in self._published_remote_ids:
            return
        self._published_remote_ids.add(remote_id)
        button_types = ALL_BUTTON_TYPES
        object_id = f"switchbot_urc_remote_{remote_id}"
        remote_topic = f"{self._topic}/{remote_id}"
        device = {
            "identifiers": [object_id],
            "name": f"SwitchBot URC Remote {remote_id.upper()}",
            "manufacturer": "SwitchBot",
            "model": "WoRWS logical native remote",
            "sw_version": "0.19.32",
            "via_device": "switchbot_urc_bridge",
        }
        event_payload = {
            "name": "Button",
            "state_topic": remote_topic,
            "event_types": button_types,
            "unique_id": f"{object_id}_button",
            "device": device,
        }
        self._client.publish(
            f"homeassistant/event/{object_id}/button/config",
            json.dumps(event_payload),
            retain=True,
        )

        any_trigger = {
            "automation_type": "trigger",
            "platform": "device_automation",
            "type": "button_short_press",
            "subtype": "any_button",
            "topic": remote_topic,
            "device": device,
        }
        self._client.publish(
            f"homeassistant/device_automation/{object_id}/any_button/config",
            json.dumps(any_trigger),
            retain=True,
        )
        for label in button_types:
            subtype = label.lower()
            trigger = {
                "automation_type": "trigger",
                "platform": "device_automation",
                "type": "button_short_press",
                "subtype": subtype,
                "topic": remote_topic,
                "payload": label,
                "value_template": "{{ value_json.button }}",
                "device": device,
            }
            self._client.publish(
                f"homeassistant/device_automation/{object_id}/{subtype}/config",
                json.dumps(trigger),
                retain=True,
            )
        _LOG.info("published HA discovery for logical remote %s", remote_id)

    def _publish_remote_button_discovery(
        self, remote_id: str, button_id: str, label: str
    ) -> None:
        """Publish a key-specific UI trigger after a tagged key is first observed."""
        if not self._client or not self._discovery:
            return
        published = getattr(self, "_published_remote_buttons", None)
        if published is None:
            published = self._published_remote_buttons = set()
        identity = (remote_id, button_id)
        if identity in published:
            return
        published.add(identity)
        object_id = f"switchbot_urc_remote_{remote_id}"
        trigger = {
            "automation_type": "trigger",
            "platform": "device_automation",
            "type": "button_short_press",
            "subtype": button_id,
            "topic": f"{self._topic}/{remote_id}",
            "payload": button_id,
            "value_template": "{{ value_json.button_id }}",
            "device": {
                "identifiers": [object_id],
                "name": f"SwitchBot URC Remote {remote_id.upper()}",
                "manufacturer": "SwitchBot",
                "model": "WoRWS logical native remote",
                "sw_version": "0.19.32",
                "via_device": "switchbot_urc_bridge",
            },
        }
        self._client.publish(
            f"homeassistant/device_automation/{object_id}/{button_id}/config",
            json.dumps(trigger),
            retain=True,
        )
        _LOG.info(
            "published HA trigger for logical remote %s button %s (%s)",
            remote_id,
            button_id,
            label,
        )

    def publish(
        self,
        label: str,
        raw_hex: str,
        remote_id: str | None = None,
        remote_slot: int | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "button": label,
            "raw": raw_hex,
            "event_type": label,
        }
        try:
            metadata = decode_event_metadata(bytes.fromhex(raw_hex))
        except ValueError:
            metadata = {"command": raw_hex, "metadata_version": 0}
        payload.update(metadata)
        if remote_id is not None:
            payload["remote_id"] = remote_id
            self._publish_remote_discovery(remote_id)
        if remote_slot is not None:
            payload["remote_slot"] = remote_slot
        if self._remote_address:
            payload["worws_address"] = self._remote_address
        button_id = payload.get("button_id")
        if remote_id is not None and button_id is not None:
            self._publish_remote_button_discovery(remote_id, str(button_id), label)
        msg = json.dumps(payload)
        if self._client:
            self._client.publish(self._topic, msg)
            if remote_id is not None:
                self._client.publish(f"{self._topic}/{remote_id}", msg)
        _LOG.info(
            "button -> %s remote_id=%s remote_slot=%s (%s)",
            label,
            remote_id or "legacy",
            remote_slot if remote_slot is not None else "unknown",
            raw_hex,
        )


def main() -> None:
    adapter = os.environ.get("ADAPTER", "hci1")
    remote_address = os.environ.get("REMOTE_ADDRESS", "").strip()
    name = os.environ.get("NAME", "HASS Light")
    topic = os.environ.get("TOPIC", "switchbot_urc/button")
    discovery = os.environ.get("DISCOVERY", "true").lower() == "true"
    diagnostic_scan = os.environ.get("DIAGNOSTIC_SCAN", "false").lower() == "true"
    hci_trace = os.environ.get("HCI_TRACE", "true").lower() == "true"
    prewarm_cache = os.environ.get("PREWARM_REMOTE_CACHE", "true").lower() == "true"
    direct_att = os.environ.get("DIRECT_ATT", "true").lower() == "true"
    try:
        raw_att_idle_timeout = float(
            os.environ.get("RAW_ATT_IDLE_TIMEOUT", RAW_ATT_IDLE_TIMEOUT)
        )
    except ValueError:
        raw_att_idle_timeout = RAW_ATT_IDLE_TIMEOUT
    try:
        raw_att_keepalive_interval = max(
            0.0,
            float(
                os.environ.get(
                    "RAW_ATT_KEEPALIVE_INTERVAL", RAW_ATT_KEEPALIVE_INTERVAL
                )
            ),
        )
    except ValueError:
        raw_att_keepalive_interval = RAW_ATT_KEEPALIVE_INTERVAL
    try:
        raw_att_keepalive_window = max(
            0.0,
            float(os.environ.get("RAW_ATT_KEEPALIVE_WINDOW", RAW_ATT_KEEPALIVE_WINDOW)),
        )
    except ValueError:
        raw_att_keepalive_window = RAW_ATT_KEEPALIVE_WINDOW
    # The ctr-key we assigned to the remote for this device (urc_test --secret-key / 0F 20 09).
    key_hex = os.environ.get("DEVICE_KEY") or "00112233445566778899aabbccddeeff"
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as err:
        raise SystemExit("DEVICE_KEY must be exactly 32 hexadecimal characters") from err
    if len(key) != 16:
        raise SystemExit("DEVICE_KEY must be exactly 32 hexadecimal characters")

    mq = Mqtt(topic, discovery, remote_address)

    import dbus
    import dbus.service
    from bluezero import adapter as bz_adapter
    from bluezero import advertisement as bz_advertisement
    from bluezero import peripheral as bz_peripheral

    try:
        adapter_name, adapter_address = resolve_bluez_adapter(adapter)
    except RuntimeError as err:
        raise SystemExit(str(err)) from err
    adapters = [str(item).upper() for item in bz_adapter.list_adapters()]
    if adapter_address not in adapters:
        raise SystemExit(
            f"BlueZ resolved {adapter_name} to {adapter_address}, but bluezero only listed: "
            f"{adapters}"
        )
    dev = bz_adapter.Adapter(adapter_address)
    mac = dev.address
    _LOG.info(
        "adapter %s resolved to MAC=%s — bind remotes' target MAC to THIS address",
        adapter_name,
        mac,
    )

    # Live traces proved that a cached database does not prevent BlueZ's reverse validation. The
    # central-mode prewarm also leaves delayed connections behind and can starve RegisterApplication
    # until BlueZ returns "No object received". Keep the option readable for configuration-file
    # compatibility, but deliberately do not perform prewarm anymore.
    if prewarm_cache:
        _LOG.warning(
            "prewarm_remote_cache is deprecated and ignored; the direct ATT server "
            "replaces the ineffective cache workaround"
        )

    set_adapter_connection_parameters(adapter_name)

    # Restore the remote-specific profile immediately before advertising. A direct 0.11.13 live
    # comparison showed that suppressing this early signaling exchange made every retry terminate
    # during Include discovery; 0.11.12 progressed through CCCD and delivered the command.
    # `remote_address` is a diagnostic aid and is optional: without it the bridge still serves
    # any WoRWS that connects, it just cannot pre-load per-peer connection parameters or filter
    # the HCI trace down to one peer.
    if remote_address:
        load_remote_connection_parameters(adapter_name, remote_address)
    else:
        _LOG.info("no remote_address configured; per-peer connection parameters are skipped")

    if hci_trace:
        HciTrace(adapter_name, remote_address or None).start()

    monitor = WoRwsAdvertisementMonitor(adapter_name, remote_address, diagnostic_scan)
    monitor.start()

    # Bluezero 0.9.0 does not expose BlueZ's MinInterval/MaxInterval properties and
    # therefore falls back to this controller's 1280 ms default.  A remote only scans
    # briefly after a key press, so advertise at the controller's minimum 20 ms interval.
    bz_advertisement.Advertisement = fast_advertisement_class(
        bz_advertisement.Advertisement, dbus, interval_ms=20
    )
    periph = bz_peripheral.Peripheral(mac, local_name=name)
    periph.add_service(srv_id=1, uuid=SVC, primary=True)

    # Bluezero advertises every primary 128-bit GATT UUID automatically. A real native SwitchBot
    # target does not: discovery uses compact FD3D service data plus company 0x0969 manufacturer
    # data, then the remote discovers cba20d00 only after connecting. Advertising all three fields
    # exceeds the 31-byte legacy packet. Keep the service primary in GATT, but omit its UUID from
    # the advertisement and reproduce the native WoStrip discovery payload instead.
    periph.primary_services.clear()
    service_data, manufacturer_data = native_strip_advertisement(mac)
    raw_advertiser = RawMgmtAdvertiser(
        adapter_name,
        raw_native_advertisement(service_data, manufacturer_data),
    )
    periph.advert.service_data = {FD3D: service_data}
    periph.advert.manufacturer_data(0x0969, manufacturer_data)
    _LOG.info(
        "configured native WoStrip advertisement "
        "(interval=20ms connection_range=%.2f-%.2fms FD3D=%s "
        "company=0x0969 payload=%s)",
        WORWS_CONN_MIN * 1.25,
        WORWS_CONN_MAX * 1.25,
        bytes(service_data).hex(),
        bytes(manufacturer_data).hex(),
    )

    device = None
    raw_protocol = FastAttProtocol(lambda value: device.on_write(value))
    raw_att_server = RawAttServer(
        mac,
        raw_protocol,
        idle_timeout=raw_att_idle_timeout,
        keepalive_interval=raw_att_keepalive_interval,
        keepalive_window=raw_att_keepalive_window,
    )

    def _notify(data: bytes) -> None:
        if raw_att_server.listener is not None:
            raw_protocol.notify(data)
        else:
            # Native order is write first, notify second.
            periph.characteristics[1].set_value(list(data))
            _LOG.info("device -> notify: %s", data.hex())

    device = SwitchBotDevice(
        key,
        _notify,
        lambda label, ph, remote_id, remote_slot: mq.publish(
            label, ph, remote_id, remote_slot
        ),
    )

    add_bridge_characteristics(periph, device)

    connected_peers: set[str] = set()

    def _connected(ble_device) -> None:
        peer = str(getattr(ble_device, "address", ble_device)).upper()
        connected_peers.add(peer)
        _LOG.info("PERIPHERAL CONNECTED peer=%s", peer)

    def _disconnected(_adapter_address, device_address) -> None:
        peer = str(device_address).upper()
        if peer in connected_peers:
            connected_peers.discard(peer)
            _LOG.info("PERIPHERAL DISCONNECTED peer=%s", peer)

    periph.on_connect = _connected
    periph.on_disconnect = _disconnected

    if direct_att:
        raw_att_server.start()
    else:
        _LOG.info("direct ATT transport disabled; using BlueZ GATT")

    bridge_state = {"paused": False}

    def _bridge_control(action: str) -> bool:
        if action == "pause":
            if bridge_state["paused"]:
                # Idempotent: a retry/duplicate request while already paused is a no-op success.
                _LOG.info("native bridge already paused; no-op")
                return True
            if raw_att_server.listener is None:
                raise RuntimeError("bridge pause requires direct ATT transport")
            raw_advertiser.remove()
            raw_att_server.disconnect_peer()
            # Release the fixed ATT CID (0x0004). While the raw server owns it, BlueZ cannot own
            # the ATT channel for the central management connection, so the remote's GATT link is
            # torn down immediately after it connects (observed: connect -> disconnect -> timeout).
            raw_att_server.close()
            bridge_state["paused"] = True
            # Closing the host socket is immediate, but the WoRWS controller reports the radio
            # disconnect up to ~1.9 s later. A 0.5 s pause worked only when the bridge link was
            # already idle; with the bounded keepalive active, management could connect too early
            # and its get-random write would receive no IV. Always allow a full 2.5 s teardown,
            # then continue waiting (up to 6 s total) while BlueZ still sees the remote connected.
            started = time.monotonic()
            minimum_release_at = started + 2.5
            release_deadline = started + 6.0
            wanted_peer = remote_address.upper()
            while time.monotonic() < minimum_release_at or (
                wanted_peer in connected_peers and time.monotonic() < release_deadline
            ):
                time.sleep(0.1)
            if wanted_peer in connected_peers:
                _LOG.warning(
                    "WoRWS still appears connected after bridge pause; management will retry"
                )
            _LOG.info(
                "native bridge paused for WoRWS management "
                "(ATT listener released, radio settled in %.1fs)",
                time.monotonic() - started,
            )
            return True
        # resume: re-acquire the ATT CID and re-advertise the fake device.
        if not bridge_state["paused"]:
            _LOG.info("native bridge already running; resume no-op")
            return True
        if raw_att_server.listener is None:
            raw_att_server.start()
        raw_advertiser.register()
        bridge_state["paused"] = False
        _LOG.info("native bridge resumed after WoRWS management")
        return True

    mq.set_control_handler(
        _bridge_control,
        adapter_name=adapter_name,
        adapter_address=adapter_address,
    )

    # Keep the legacy advertisement compact. Advertising the native FD3D/manufacturer payload and
    # the 128-bit GATT UUID together would exceed the controller's 31-byte legacy packet.

    def _shutdown(*_args) -> None:
        raw_att_server.close()
        raw_advertiser.remove()
        os._exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    _LOG.info("registering minimal connectable advertisement as %r", name)
    publish_with_retry(
        periph,
        raw_advertiser=raw_advertiser,
        raw_att_server=raw_att_server,
    )


if __name__ == "__main__":
    main()
