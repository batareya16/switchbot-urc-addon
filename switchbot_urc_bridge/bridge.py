#!/usr/bin/env python3
"""SwitchBot URC Bridge add-on: fake native target for the WoRWS button channel.

Firmware analysis confirms that a native press makes the WoRWS act as a BLE central: it connects
to the MAC saved by 0F 20 08, discovers cba20d00/cba20002/cba20003, performs the 0F 21 03 session
handshake, and writes the encrypted device command.

Config comes from environment variables set by run.sh:
  ADAPTER                     Bluetooth controller used by the raw HCI bridge
  REMOTE_ADDRESS              BLE MAC of the physical WoRWS being observed
  TOPIC                       MQTT button event topic
  DISCOVERY                   Publish HA MQTT discovery
  HCI_TRACE "true"/"false"    log controller diagnostics plus one remote ATT session
  MQTT_HOST/MQTT_PORT/MQTT_USER/MQTT_PASS  broker (from the MQTT service)
"""
from __future__ import annotations

from contextlib import suppress
import json
import logging
import os
import pathlib
import signal
import struct
import subprocess
import tempfile
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import hci_multi

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_LOG = logging.getLogger("bridge")
BRIDGE_VERSION = "0.32.4"

SVC = "cba20d00-224d-11e6-9fb8-0002a5d5c51b"
CHAR_WRITE = "cba20002-224d-11e6-9fb8-0002a5d5c51b"
CHAR_NOTIFY = "cba20003-224d-11e6-9fb8-0002a5d5c51b"


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
BRIDGE_ADV_INTERVAL = 0x0020  # 20 ms in Bluetooth's 0.625 ms units.

HCI_TRACE_MARKERS = (
    "LE Set Advertising",
    "LE Set Extended Advertising",
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


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


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


def _write_json_atomically(path: pathlib.Path, payload) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
            temporary = pathlib.Path(output.name)
            json.dump(payload, output)
        temporary.replace(path)
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)


class SwitchBotDevice:
    """Receive open button commands from WoRWS Native remotes."""

    def __init__(self, notify, on_button) -> None:
        self._notify = notify
        self._on_button = on_button
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
        _LOG.info("unhandled write: %s", raw.hex())


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

    def begin_session(self) -> None:
        """Reset the bounded per-connection trace used in normal INFO logs."""
        self.session_stages = []
        self.session_writes = 0
        self.session_start = time.monotonic()
        self.subscribe_time = None
        self.device_write_time = None
        self.ack_time = None

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
        if self.ack_time is None:
            self.ack_time = time.monotonic()
        _LOG.info("device -> raw ATT notify: %s", data.hex())


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
        self, handler, *, adapter_name: str, adapter_address: str, capabilities=None,
        management_runner,
    ) -> None:  # noqa: ANN001
        """Subscribe to raw HCI management and address requests.

        `capabilities` is republished with every status and identity message, because it is how
        Remote Studio learns how many native tiles this controller can carry without anyone
        having to read an add-on log.
        """
        if self._client is None:
            return

        bridge_identity = {
            "adapter": adapter_name,
            "adapter_address": adapter_address.upper(),
            **(dict(capabilities) if capabilities else {}),
        }
        self._bridge_identity = bridge_identity

        def _republish_identity() -> None:
            """Refresh the retained identity after the bridge's capabilities change."""
            if self._client is None:
                return
            payload = json.dumps(self._bridge_identity)
            self._client.publish("switchbot_urc/bridge/info", payload, qos=1, retain=True)
            if hci_multi.is_address(adapter_address):
                topic = f"switchbot_urc/bridge/info/{hci_multi.normalise(adapter_address)}"
                self._client.publish(topic, payload, qos=1, retain=True)

        self.republish_identity = _republish_identity
        manage_lock = threading.Lock()
        management_results: dict[str, dict] = {}

        def _run_management(client, payload: dict) -> None:  # noqa: ANN001
            """Execute a serialized transaction on the selected bridge transport."""
            request_id = str(payload.get("request_id", ""))
            result: dict = {"ok": False, "failed_stage": "bridge", "error": "not started"}
            # Serialize operations and cache their result so MQTT redelivery cannot run a
            # command sequence twice.
            with manage_lock:
                if request_id and request_id in management_results:
                    client.publish(
                        "switchbot_urc/bridge/manage_result",
                        json.dumps({"request_id": request_id, **management_results[request_id], **bridge_identity}),
                        qos=1,
                    )
                    return
                try:
                    steps = list(payload.get("steps", []))
                    result = management_runner(str(payload["address"]), str(payload["key"]),
                                               int(payload["key_id"]), steps)
                    if not isinstance(result, dict) or "ok" not in result:
                        raise RuntimeError("raw HCI management returned an invalid result")
                    result.setdefault("transport", "raw_hci")
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
                    result = {"ok": False, "failed_stage": "bridge", "error": str(err),
                              "transport": "raw_hci"}
                    _LOG.exception("raw HCI management failed")
                finally:
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
            if action in {"addresses", "check_address"}:
                meant_for = str(payload.get("adapter_address") or "")
                if meant_for and hci_multi.normalise(meant_for) != hci_multi.normalise(adapter_address):
                    return
            ok = False
            error = ""
            try:
                if action not in {"addresses", "check_address"}:
                    raise ValueError(f"unsupported bridge action: {action}")
                ok = bool(handler(action, payload))
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
            _republish_identity()

        def _on_connect(client, _userdata, _flags, _reason_code, _properties=None) -> None:  # noqa: ANN001
            # paho uses a clean session by default, so the broker drops every subscription on an
            # unexpected disconnect. Re-subscribe after reconnect so management remains available
            # after a broker restart.
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
            "sw_version": BRIDGE_VERSION,
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
            "sw_version": BRIDGE_VERSION,
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
                "sw_version": BRIDGE_VERSION,
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


# Addresses added at run time have to survive a restart, or a tile bound to one stops working
# the next time the add-on starts. /data is the add-on's own persistent store.
_ADDRESS_STORE = pathlib.Path("/data/addresses.json")


def _remember_addresses(values: list[str]) -> None:
    try:
        _ADDRESS_STORE.parent.mkdir(parents=True, exist_ok=True)
        _write_json_atomically(_ADDRESS_STORE, values)
    except OSError as err:
        _LOG.warning("could not persist the served addresses: %s", err)


def _recall_addresses() -> list[str]:
    try:
        values = json.loads(_ADDRESS_STORE.read_text())
    except (OSError, ValueError):
        return []
    return [str(item) for item in values if isinstance(item, str)] if isinstance(
        values, list) else []


def run_multi_address(
    adapter: str,
    configured: list[str],
    mq: "Mqtt",
    remote_address: str,
) -> None:
    """Run the peripheral and native management client on the same raw HCI controller."""
    name, index, own = hci_multi.resolve_adapter(adapter)
    extended, sets = hci_multi.probe_capabilities(index)
    if not extended:
        raise RuntimeError(f"{name} does not report extended advertising support. "
                           "SwitchBot URC Bridge requires a compatible Bluetooth 5 controller.")
    _LOG.info("%s (%s): extended advertising with %d set(s)", name, own or "address unknown", sets)
    remembered = _recall_addresses()
    addresses = [*configured, *remembered]

    server = hci_multi.MultiAddressServer(
        name,
        addresses,
        protocol_factory=FastAttProtocol,
        device_factory=lambda notify, _address_of: SwitchBotDevice(
            notify,
            lambda label, ph, remote_id, remote_slot: mq.publish(
                label, ph, remote_id=remote_id, remote_slot=remote_slot
            ),
        ),
        conn_min=WORWS_CONN_MIN,
        conn_max=WORWS_CONN_MAX,
        advertising_interval_ms=BRIDGE_ADV_INTERVAL * 0.625,
        auto_fill=True,
    )

    def _shutdown(*_args) -> None:
        server.stop()
        os._exit(0)

    if os.environ.get("HCI_TRACE", "false").lower() == "true":
        HciTrace(name, remote_address or None).start()
    server.start()
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    _remember_addresses(list(dict.fromkeys([*server.addresses, *remembered])))

    def _control(action: str, payload: dict | None = None) -> bool:
        if action == "check_address":
            return server.serves_address(str((payload or {}).get("address") or ""))
        # "addresses": Remote Studio allocated a new address and needs this controller to serve
        # it before the tile bound to it is ever pressed.
        wanted = list((payload or {}).get("addresses") or [])
        served = server.set_addresses(wanted)
        _remember_addresses(served)
        mq._bridge_identity.update(server.capabilities())
        mq.republish_identity()
        return True

    mq.set_control_handler(
        _control,
        adapter_name=adapter,
        adapter_address=server.own_public,
        capabilities=server.capabilities(),
        management_runner=lambda address, key_hex, key_id, steps: server.manage_remote(
            address, key_hex, key_id, steps, crypt=aes_ctr),
    )
    _LOG.info(
        "multi-address bridge running on %s for %s; advertising interval %.2f ms",
        adapter,
        ", ".join(server.addresses),
        server.interval * 0.625,
    )
    while True:
        time.sleep(3600)


def main() -> None:
    adapter = os.environ.get("ADAPTER", "hci1")
    remote_address = os.environ.get("REMOTE_ADDRESS", "").strip()
    topic = os.environ.get("TOPIC", "switchbot_urc/button")
    discovery = os.environ.get("DISCOVERY", "true").lower() == "true"
    mq = Mqtt(topic, discovery, remote_address)

    configured = [item.strip() for item in os.environ.get("ADDRESSES", "").split(",")
                  if item.strip()]
    try:
        run_multi_address(adapter, configured, mq, remote_address)
    except (RuntimeError, OSError) as err:
        raise SystemExit(f"Could not start the raw HCI bridge on {adapter}: {err}") from err


if __name__ == "__main__":
    main()
