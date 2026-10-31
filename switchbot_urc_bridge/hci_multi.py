"""Serve the native channel on several BLE addresses from one controller.

A native tile connects to one fixed address and the WoRWS keeps its target key per six-byte
address, so several tiles need several addresses. BlueZ cannot provide them: none of the
kernel's advertising commands carries an address field, so every advertising instance goes out
as the controller's identity. A Bluetooth 5 controller can, through
`LE Set Advertising Set Random Address`, but reaching that command means taking the controller
on the HCI user channel, which detaches the kernel's Bluetooth stack from it.

What the kernel used to do then has to happen here: HCI, ACL with fragment reassembly and
buffer credits, and L2CAP on the fixed ATT channel. ATT itself is not reimplemented —
`FastAttProtocol` and `SwitchBotDevice` from bridge.py are transport-free and are used as they
are, one pair per connection. There is no LE pairing in this path; the remote encrypts at the
application layer.

Proven on hardware before this module existed, with `tools/spike_multi_address.py` and
`tools/hci_multi_bridge.py`; see the "Several addresses from one controller" section of
PROTOCOL.md.
"""
from __future__ import annotations

import ctypes
import logging
import os
import pathlib
import select
import socket
import struct
import threading
import time
from typing import Callable

_LOG = logging.getLogger("bridge.hci")

HCI_CHANNEL_CONTROL = 3
HCI_CHANNEL_USER = 1
HCI_DEV_NONE = 0xFFFF
HCI_COMMAND_PKT = 0x01
HCI_ACL_PKT = 0x02
HCI_EVENT_PKT = 0x04

MGMT_OP_SET_POWERED = 0x0005
MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002

OP_RESET = 0x0C03
OP_SET_EVENT_MASK = 0x0C01
OP_READ_BUFFER_SIZE = 0x1005
OP_READ_BD_ADDR = 0x1009
OP_LE_SET_EVENT_MASK = 0x2001
OP_LE_READ_BUFFER_SIZE = 0x2002
OP_LE_SET_ADV_SET_RANDOM_ADDR = 0x2035
OP_LE_SET_EXT_ADV_PARAMS = 0x2036
OP_LE_SET_EXT_ADV_DATA = 0x2037
OP_LE_SET_EXT_ADV_ENABLE = 0x2039
OP_LE_READ_ADV_SETS = 0x203B

EV_DISCONN_COMPLETE = 0x05
EV_CMD_COMPLETE = 0x0E
EV_CMD_STATUS = 0x0F
EV_NUM_COMPLETED_PACKETS = 0x13
EV_LE_META = 0x3E
STATUS_UNKNOWN_COMMAND = 0x01
LE_CONNECTION_COMPLETE = 0x01
LE_ENHANCED_CONNECTION_COMPLETE = 0x0A
LE_ADV_SET_TERMINATED = 0x12

# Subevents 1..32. A narrower mask hides LE Advertising Set Terminated (0x12), which needs
# bit 17 and is the only event naming the set a connection arrived on.
LE_EVENT_MASK = bytes.fromhex("ffffffff00000000")
ATT_CID = 0x0004
PB_FIRST = 0x00
PB_CONTINUE = 0x01


def normalise(address: str) -> str:
    return address.replace(":", "").replace("-", "").upper()


def format_address(address: str) -> str:
    """The canonical colon-separated upper-case form, for logs and for the integration."""
    compact = normalise(address)
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def address_bytes(address: str) -> bytes:
    raw = bytes.fromhex(normalise(address))
    if len(raw) != 6:
        raise ValueError(f"{address!r} is not a six-byte Bluetooth address")
    return raw[::-1]


def advertisement_for(address: str, conn_min: int, conn_max: int) -> bytes:
    """The idle-WoStrip payload carrying this set's own address.

    Mirrors `native_strip_advertisement` and `raw_native_advertisement` in bridge.py, plus the
    Flags structure the kernel adds in managed mode and nobody adds on the user channel.
    """
    mac = bytes.fromhex(normalise(address))
    manufacturer = list(mac) + [0x01, 0xE4, 0x22] + [0x00] * 4
    payload = (
        bytes([0x02, 0x01, 0x06])
        + bytes([1 + 2 + len(manufacturer), 0xFF, 0x69, 0x09, *manufacturer])
        + bytes([1 + 2 + 1, 0x16, 0x3D, 0xFD, 0x72])
        + bytes([0x05, 0x12, *struct.pack("<HH", conn_min, conn_max)])
    )
    if len(payload) > 31:
        raise ValueError("advertisement does not fit a legacy PDU")
    return payload


def set_powered(index: int, powered: bool, timeout: float = 5.0) -> str:
    """Power a controller on or off through the kernel's management interface."""
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_hci = getattr(socket, "BTPROTO_HCI", 1)
    sock_type = socket.SOCK_RAW | getattr(socket, "SOCK_CLOEXEC", 0)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.socket(af_bluetooth, sock_type, btproto_hci)
    if fd < 0:
        return f"socket failed: {os.strerror(ctypes.get_errno())}"
    address = struct.pack("=HHH", af_bluetooth, HCI_DEV_NONE, HCI_CHANNEL_CONTROL)
    if libc.bind(fd, address, len(address)) < 0:
        error = ctypes.get_errno()
        os.close(fd)
        return f"control channel unavailable: {os.strerror(error)}"
    sock = socket.socket(af_bluetooth, sock_type, btproto_hci, fileno=fd)
    try:
        sock.settimeout(timeout)
        sock.send(struct.pack("<HHH", MGMT_OP_SET_POWERED, index, 1)
                  + bytes([1 if powered else 0]))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = sock.recv(1024)
            if len(event) < 9:
                continue
            code, event_index, length = struct.unpack_from("<HHH", event)
            body = event[6:6 + length]
            if event_index != index or code not in (MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS):
                continue
            command, status = struct.unpack_from("<HB", body)
            if command != MGMT_OP_SET_POWERED:
                continue
            return "ok" if status == 0 else f"status 0x{status:02x}"
        return "timed out"
    except OSError as err:
        return str(err)
    finally:
        sock.close()


def resolve_adapter(selector: str) -> tuple[str, int, str]:
    """Resolve ``hciN`` or a controller MAC to ``(name, index, address)`` through sysfs.

    Kernel adapter numbering is not stable: a reboot or a replug can swap hci0 and hci1, which
    silently points the bridge at the wrong radio. Reading sysfs rather than asking BlueZ also
    keeps this working when bluetoothd's D-Bus connection is wedged, which is a failure mode
    this add-on has had to survive before.
    """
    wanted = selector.strip()
    wanted_address = normalise(wanted) if ":" in wanted or len(wanted) == 12 else ""
    root = pathlib.Path("/sys/class/bluetooth")
    available: list[str] = []
    for entry in sorted(root.glob("hci*")) if root.is_dir() else []:
        try:
            address = entry.joinpath("address").read_text().strip().upper()
        except OSError:
            continue
        available.append(f"{entry.name}={address}")
        index = int(entry.name.removeprefix("hci"))
        if entry.name == wanted or (wanted_address and normalise(address) == wanted_address):
            return entry.name, index, address
    if not wanted_address and wanted.startswith("hci") and wanted[3:].isdigit():
        # sysfs is unavailable but the selector is unambiguous; take it at face value.
        return wanted, int(wanted[3:]), ""
    raise RuntimeError(
        f"Bluetooth adapter {selector!r} was not found; available: "
        + (", ".join(available) or "none")
    )


class HciCommandError(OSError):
    """A command the controller refused, keeping its status for callers that care."""

    def __init__(self, opcode: int, status: int) -> None:
        self.opcode = opcode
        self.status = status
        super().__init__(f"command 0x{opcode:04x} failed with status 0x{status:02x}")


MGMT_OP_READ_ADV_FEATURES = 0x003D
# Read Advertising Features flags saying the controller does extended advertising. Without
# any of them it is a Bluetooth 4 radio and one address is all it will ever offer.
ADV_FLAG_EXTENDED = 0x0080 | 0x0100 | 0x0200


def probe_capabilities(index: int, timeout: float = 3.0) -> tuple[bool, int]:
    """Ask the kernel what this controller can advertise, without taking it away from BlueZ.

    Returns ``(does extended advertising, advertising sets)``. This is a plain read on the
    management socket, so it is safe to call before deciding which path to run: claiming the
    user channel powers the controller down, and doing that to find out it was pointless would
    interrupt whatever BlueZ was doing with it.
    """
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_hci = getattr(socket, "BTPROTO_HCI", 1)
    sock_type = socket.SOCK_RAW | getattr(socket, "SOCK_CLOEXEC", 0)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.socket(af_bluetooth, sock_type, btproto_hci)
    if fd < 0:
        return False, 1
    address = struct.pack("=HHH", af_bluetooth, HCI_DEV_NONE, HCI_CHANNEL_CONTROL)
    if libc.bind(fd, address, len(address)) < 0:
        os.close(fd)
        return False, 1
    sock = socket.socket(af_bluetooth, sock_type, btproto_hci, fileno=fd)
    try:
        sock.settimeout(timeout)
        sock.send(struct.pack("<HHH", MGMT_OP_READ_ADV_FEATURES, index, 0))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = sock.recv(1024)
            if len(event) < 9:
                continue
            code, event_index, length = struct.unpack_from("<HHH", event)
            body = event[6:6 + length]
            if event_index != index or code not in (MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS):
                continue
            command, status = struct.unpack_from("<HB", body)
            if command != MGMT_OP_READ_ADV_FEATURES:
                continue
            if status or len(body) < 3 + 7:
                return False, 1
            flags, _max_adv, _max_scan, sets = struct.unpack_from("<IBBB", body, 3)
            return bool(flags & ADV_FLAG_EXTENDED), max(1, sets)
        return False, 1
    except OSError:
        return False, 1
    finally:
        sock.close()


def plan_mode(
    extended: bool,
    sets: int,
    own_address: str,
    configured: list[str],
    remembered: list[str],
) -> tuple[bool, list[str], str]:
    """Decide which path to run and which addresses to serve.

    Kept free of sockets so the decision can be tested on its own. Returns
    ``(serve several addresses, the list, why)``. The controller's own address always comes
    first: every tile bound before any of this existed points at it.
    """
    wanted: list[str] = []
    for item in [own_address, *configured, *remembered]:
        if not item or not is_address(item):
            continue
        if not any(normalise(item) == normalise(seen) for seen in wanted):
            wanted.append(format_address(normalise(item)))
    if not wanted:
        return False, [], "no usable address is known for this controller"
    if not extended:
        if len(configured) > 1:
            return False, wanted[:1], (
                f"{len(configured)} addresses are configured, but this controller does not do "
                "extended advertising and can only ever serve one"
            )
        return False, wanted[:1], "this controller does not do extended advertising"
    if len(wanted) > sets:
        kept, dropped = wanted[:sets], wanted[sets:]
        return True, kept, (
            f"this controller has {sets} advertising set(s), so {', '.join(dropped)} "
            "cannot be served"
        )
    return True, wanted, f"extended advertising with {sets} set(s)"


def is_address(value: str) -> bool:
    compact = normalise(value)
    return len(compact) == 12 and all(char in "0123456789ABCDEF" for char in compact)


class UserChannel:
    """Exclusive raw HCI access to one controller."""

    def __init__(self, index: int) -> None:
        self.index = index
        af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
        btproto_hci = getattr(socket, "BTPROTO_HCI", 1)
        sock_type = socket.SOCK_RAW | getattr(socket, "SOCK_CLOEXEC", 0)
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.socket(af_bluetooth, sock_type, btproto_hci)
        if fd < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        address = struct.pack("=HHH", af_bluetooth, index, HCI_CHANNEL_USER)
        if libc.bind(fd, address, len(address)) < 0:
            error = ctypes.get_errno()
            os.close(fd)
            raise OSError(error, os.strerror(error))
        self.sock = socket.socket(af_bluetooth, sock_type, btproto_hci, fileno=fd)
        # Non-event packets seen while waiting for a command reply, kept so a caller reading
        # ACL data never loses a frame to a concurrent command.
        self.spare: list[tuple[int, bytes]] = []

    def close(self) -> None:
        self.sock.close()

    def read(self, timeout: float):
        if self.spare:
            return self.spare.pop(0)
        if timeout <= 0:
            return None
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return None
        packet = self.sock.recv(2048)
        return (packet[0], packet[1:]) if len(packet) >= 2 else None

    def events(self, timeout: float):
        packet = self.read(timeout)
        if packet is None:
            return
        kind, body = packet
        if kind != HCI_EVENT_PKT:
            self.spare.append(packet)
            return
        if len(body) >= 2:
            yield body[0], body[2:2 + body[1]]

    def command(self, opcode: int, payload: bytes = b"", timeout: float = 3.0) -> bytes:
        self.sock.send(
            bytes([HCI_COMMAND_PKT]) + struct.pack("<HB", opcode, len(payload)) + payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for code, params in self.events(deadline - time.monotonic()):
                if code == EV_CMD_COMPLETE:
                    _count, returned = struct.unpack_from("<BH", params)
                    if returned == opcode:
                        if params[3]:
                            raise HciCommandError(opcode, params[3])
                        return params[4:]
                elif code == EV_CMD_STATUS:
                    status, _count, returned = struct.unpack_from("<BBH", params)
                    if returned == opcode:
                        if status:
                            raise HciCommandError(opcode, status)
                        return b""
        raise TimeoutError(f"command 0x{opcode:04x} got no answer")


class Link:
    """One live connection: ACL reassembly plus the protocols serving it."""

    def __init__(self, handle: int, address: str, protocol, device) -> None:
        self.handle = handle
        self.address = address
        self.protocol = protocol
        self.device = device
        self.pending = bytearray()
        self.expected = 0

    def feed(self, payload: bytes, first: bool):
        """Reassemble L2CAP B-frames; yield each complete ATT PDU."""
        if first:
            if self.pending:
                _LOG.warning("dropping %d incomplete bytes on handle %d",
                             len(self.pending), self.handle)
            self.pending = bytearray(payload)
        else:
            self.pending.extend(payload)
        self._resize()
        while self.expected and len(self.pending) >= self.expected:
            frame = bytes(self.pending[:self.expected])
            del self.pending[:self.expected]
            if struct.unpack_from("<H", frame, 2)[0] == ATT_CID:
                yield frame[4:]
            self._resize()

    def _resize(self) -> None:
        self.expected = (
            struct.unpack_from("<H", self.pending)[0] + 4 if len(self.pending) >= 4 else 0
        )


class AclWriter:
    """Fragment ATT PDUs into ACL packets and respect the controller's buffer credits."""

    def __init__(self, channel: UserChannel, payload_size: int, credits: int) -> None:
        self.channel = channel
        self.payload_size = max(27, payload_size)
        self.credits = max(1, credits)
        self.inflight = 0

    def completed(self, count: int) -> None:
        self.inflight = max(0, self.inflight - count)

    def send(self, handle: int, data: bytes) -> None:
        frame = struct.pack("<HH", len(data), ATT_CID) + data
        boundary = PB_FIRST
        while frame:
            chunk, frame = frame[:self.payload_size], frame[self.payload_size:]
            self.channel.sock.send(
                bytes([HCI_ACL_PKT])
                + struct.pack("<HH", handle | (boundary << 12), len(chunk)) + chunk)
            self.inflight += 1
            boundary = PB_CONTINUE
            if self.inflight >= self.credits:
                self._drain()

    def _drain(self, timeout: float = 1.0) -> None:
        """Wait for buffer credits. Dropping instead would lose a reply the remote waits for."""
        deadline = time.monotonic() + timeout
        while self.inflight >= self.credits and time.monotonic() < deadline:
            for code, params in self.channel.events(0.05):
                if code == EV_NUM_COMPLETED_PACKETS and params:
                    for index in range(params[0]):
                        _handle, count = struct.unpack_from("<HH", params, 1 + index * 4)
                        self.completed(count)


class MultiAddressServer:
    """Advertise and serve the native channel on several addresses from one controller."""

    def __init__(
        self,
        adapter: str,
        addresses: list[str],
        *,
        protocol_factory: Callable,
        device_factory: Callable,
        conn_min: int,
        conn_max: int,
        advertising_interval_ms: float = 100.0,
    ) -> None:
        if not addresses:
            raise ValueError("at least one address is required")
        self.adapter, self.index, self.expected_address = resolve_adapter(adapter)
        if self.adapter != adapter.strip():
            _LOG.info("adapter %r resolved to %s (%s)",
                      adapter, self.adapter, self.expected_address or "address unknown")
        self.addresses = addresses
        self.protocol_factory = protocol_factory
        self.device_factory = device_factory
        self.conn_min = conn_min
        self.conn_max = conn_max
        self.interval = max(1, int(advertising_interval_ms / 0.625))
        self.channel: UserChannel | None = None
        self.writer: AclWriter | None = None
        self.links: dict[int, Link] = {}
        self.own_public = ""
        self.advertising_sets = 0
        self.extended_advertising = False
        self._enable_frame = b""
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_set_address: str | None = None

    # -- controller ownership ------------------------------------------------------------

    def _claim(self) -> None:
        outcome = set_powered(self.index, False)
        if outcome != "ok":
            raise RuntimeError(f"could not power {self.adapter} down: {outcome}")
        channel = UserChannel(self.index)
        channel.command(OP_RESET)
        channel.command(OP_SET_EVENT_MASK, bytes.fromhex("ffffffffffffff3f"))
        channel.command(OP_LE_SET_EVENT_MASK, LE_EVENT_MASK)
        self.own_public = ":".join(
            f"{byte:02X}" for byte in reversed(channel.command(OP_READ_BD_ADDR)[:6]))
        _LOG.info("%s is the controller at %s", self.adapter, self.own_public)
        if self.expected_address and normalise(self.expected_address) != normalise(self.own_public):
            # sysfs and the controller disagree, so something renumbered under us mid-start.
            channel.close()
            set_powered(self.index, True)
            raise RuntimeError(
                f"{self.adapter} reports {self.own_public} but was expected to be "
                f"{self.expected_address}; set the adapter option to a MAC rather than hciN"
            )
        payload_size, credits = self._buffer_size(channel)

        def _give_back() -> None:
            channel.close()
            set_powered(self.index, True)

        try:
            available = channel.command(OP_LE_READ_ADV_SETS)[0]
        except HciCommandError as err:
            _give_back()
            if err.status == STATUS_UNKNOWN_COMMAND:
                # Extended advertising is a Bluetooth 5 feature; a 4.x controller does not know
                # the command at all. Adapter numbering is not stable across reboots, so the
                # usual cause is that hciN now points at a different radio.
                raise RuntimeError(
                    f"{self.adapter} ({self.own_public}) does not support extended advertising, "
                    "so it can only ever serve one address. Check that this is the Bluetooth 5 "
                    "adapter — hci numbering changes across reboots and replugs — or leave the "
                    "addresses option empty to keep the single-address BlueZ path."
                ) from None
            raise
        if len(self.addresses) > available:
            _give_back()
            raise RuntimeError(
                f"{self.adapter} ({self.own_public}) offers {available} advertising set(s) but "
                f"{len(self.addresses)} addresses were configured"
            )
        self.channel = channel
        self.advertising_sets = available
        self.extended_advertising = True
        self.writer = AclWriter(channel, payload_size, credits)
        for handle, address in enumerate(self.addresses):
            self._configure_set(handle, address)
        self._rebuild_enable_frame()
        channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
        _LOG.info("%s claimed: public %s, ACL payload %d B, %d buffers, serving %s",
                  self.adapter, self.own_public, payload_size, credits,
                  ", ".join(self.addresses))
        if not any(normalise(item) == normalise(self.own_public) for item in self.addresses):
            # Legitimate, but it is the quiet way to break every tile bound before this option
            # existed, because they all point at the controller's own address.
            _LOG.warning(
                "%s is not in the addresses list, so any tile bound to the controller's own "
                "address is no longer answered; add it if presses stopped working",
                self.own_public,
            )

    def _release(self) -> None:
        if self.channel is not None:
            try:
                self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]), timeout=1.0)
            except (OSError, TimeoutError):
                pass
            self.channel.close()
            self.channel = None
        self.writer = None
        self.links.clear()
        _LOG.info("%s returned to BlueZ: %s", self.adapter, set_powered(self.index, True))

    @staticmethod
    def _buffer_size(channel: UserChannel) -> tuple[int, int]:
        """LE buffers if the controller has its own, else the shared BR/EDR ones."""
        try:
            payload = channel.command(OP_LE_READ_BUFFER_SIZE)
            length, count = struct.unpack_from("<HB", payload)
            if length and count:
                return length, count
            payload = channel.command(OP_READ_BUFFER_SIZE)
            acl_length, _sco, acl_count, _sco_count = struct.unpack_from("<HBHH", payload)
            return acl_length, acl_count
        except (HciCommandError, struct.error) as err:
            # The spec's own minimum for LE is a 27-byte payload; assuming it costs throughput
            # we do not need, and every ATT PDU here is small.
            _LOG.warning("could not read the buffer size (%s); assuming 27 B and 4 buffers", err)
            return 27, 4

    def _configure_set(self, handle: int, address: str) -> None:
        """One connectable legacy-PDU set.

        The controller's own public address cannot be assigned to a set, so the set using it
        advertises as public instead. Reusing it keeps tiles already bound to it working.
        """
        assert self.channel is not None
        public = normalise(address) == normalise(self.own_public)
        self.channel.command(OP_LE_SET_EXT_ADV_PARAMS, struct.pack(
            "<BH3s3sBBB6sBbBBBBB",
            handle,
            0x0013,                              # connectable, scannable, legacy PDUs
            self.interval.to_bytes(3, "little"),
            self.interval.to_bytes(3, "little"),
            0x07,                                # all three primary channels
            0x00 if public else 0x01,            # own address type
            0x00, b"\x00" * 6,                   # no directed peer
            0x00, 0x7F,                          # no filter policy, no TX power preference
            0x01, 0x00, 0x01,                    # 1M primary, no skip, 1M secondary
            handle,                              # advertising SID, distinct per set
            0x00,                                # no scan request notifications
        ))
        if not public:
            self.channel.command(
                OP_LE_SET_ADV_SET_RANDOM_ADDR, bytes([handle]) + address_bytes(address))
        data = advertisement_for(address, self.conn_min, self.conn_max)
        self.channel.command(OP_LE_SET_EXT_ADV_DATA, bytes([handle, 0x03, 0x01, len(data)]) + data)

    def capabilities(self) -> dict:
        """What this controller can do, for the integration to plan against."""
        return {
            "controller": self.own_public,
            "advertising_sets": self.advertising_sets,
            "extended_advertising": self.extended_advertising,
            "serving": list(self.addresses),
            "multi_address": True,
        }

    def set_addresses(self, addresses: list[str]) -> list[str]:
        """Serve a different set of addresses, without restarting the add-on.

        The controller is reconfigured in place: an advertising set cannot change its address
        while it is enabled, so this stops advertising, rewrites every set, and starts again.
        Live connections are left alone — they are already past advertising.
        """
        wanted = [format_address(item) for item in addresses if item]
        if not wanted:
            raise ValueError("at least one address is required")
        if len(wanted) > max(1, self.advertising_sets):
            raise ValueError(
                f"{self.adapter} has {self.advertising_sets} advertising set(s), "
                f"so it cannot serve {len(wanted)} addresses"
            )
        if [normalise(item) for item in wanted] == [normalise(item) for item in self.addresses]:
            return list(self.addresses)
        if self.channel is None:
            self.addresses = wanted
            return wanted
        self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]))
        previous = self.addresses
        self.addresses = wanted
        try:
            for handle, address in enumerate(wanted):
                self._configure_set(handle, address)
        except (OSError, TimeoutError):
            # Put the working set back rather than leaving the bridge advertising nothing.
            self.addresses = previous
            for handle, address in enumerate(previous):
                self._configure_set(handle, address)
            self._rebuild_enable_frame()
            self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
            raise
        self._rebuild_enable_frame()
        self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
        _LOG.info("%s now serving %s", self.adapter, ", ".join(wanted))
        return wanted

    def _rebuild_enable_frame(self) -> None:
        frame = bytes([0x01, len(self.addresses)])
        for handle in range(len(self.addresses)):
            frame += struct.pack("<BHB", handle, 0, 0)
        self._enable_frame = frame

    # -- lifecycle -----------------------------------------------------------------------

    def start(self) -> None:
        self._claim()
        self._thread = threading.Thread(target=self._serve, name="hci-multi", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._release()

    def pause(self) -> bool:
        """Hand the controller back so the integration can run a management session on it."""
        if self._paused.is_set():
            _LOG.info("multi-address bridge already paused; no-op")
            return True
        self._paused.set()
        self._release()
        _LOG.info("multi-address bridge paused; %s is BlueZ's again", self.adapter)
        return True

    def resume(self) -> bool:
        if not self._paused.is_set():
            _LOG.info("multi-address bridge already running; resume no-op")
            return True
        self._claim()
        self._paused.clear()
        _LOG.info("multi-address bridge resumed")
        return True

    # -- the event loop ------------------------------------------------------------------

    def _rearm(self) -> None:
        """A connectable set stops advertising once used; arm them all again."""
        if self.channel is None:
            return
        try:
            self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
        except (OSError, TimeoutError) as err:
            _LOG.warning("could not re-arm the advertising sets: %s", err)

    def _open_link(self, handle: int, peer: str) -> None:
        assert self.writer is not None
        box: dict[str, object] = {}
        # The two refer to each other, so the protocol reaches its device through this box.
        # A plain closure would capture the loop variable and send an older connection's
        # writes to the newest device.
        protocol = self.protocol_factory(lambda value, b=box: b["device"].on_write(value))
        protocol.sender = lambda data, h=handle: self.writer.send(h, data)
        protocol.begin_session()
        device = self.device_factory(
            protocol.notify, lambda: self.links.get(handle).address if handle in self.links else "")
        box["device"] = device
        self.links[handle] = Link(handle, self._last_set_address or "?", protocol, device)
        _LOG.info("connected handle=%d peer=%s", handle, peer)
        # BlueZ used to start this exchange as the reverse GATT client; without it WoRWS
        # correctly refuses anything larger than the default ATT MTU of 23.
        self.writer.send(handle, b"\x02\x00\x02")

    def _serve(self) -> None:
        while not self._stop.is_set():
            if self._paused.is_set() or self.channel is None:
                time.sleep(0.1)
                continue
            try:
                packet = self.channel.read(0.5)
            except OSError as err:
                if not self._stop.is_set() and not self._paused.is_set():
                    _LOG.warning("HCI read failed: %s", err)
                continue
            if packet is None:
                continue
            kind, body = packet
            try:
                if kind == HCI_ACL_PKT:
                    self._on_acl(body)
                elif kind == HCI_EVENT_PKT and len(body) >= 2:
                    self._on_event(body[0], body[2:2 + body[1]])
            except Exception:  # noqa: BLE001 - one bad packet must not end the bridge
                _LOG.exception("failed to handle an HCI packet")

    def _on_acl(self, body: bytes) -> None:
        header, length = struct.unpack_from("<HH", body)
        handle, boundary = header & 0x0FFF, (header >> 12) & 0x03
        link = self.links.get(handle)
        if link is None or self.writer is None:
            return
        for pdu in link.feed(body[4:4 + length], boundary != PB_CONTINUE):
            response = link.protocol.handle(pdu)
            if response is not None:
                self.writer.send(handle, response)

    def _on_event(self, code: int, params: bytes) -> None:
        if code == EV_LE_META and params:
            subevent = params[0]
            if subevent in (LE_CONNECTION_COMPLETE, LE_ENHANCED_CONNECTION_COMPLETE):
                if params[1]:
                    _LOG.warning("connection failed with status 0x%02x", params[1])
                    return
                handle = struct.unpack_from("<H", params, 2)[0]
                peer = ":".join(f"{b:02X}" for b in reversed(params[6:12]))
                self._open_link(handle, peer)
            elif subevent == LE_ADV_SET_TERMINATED:
                # This arrives around the connection event, in no guaranteed order, and is the
                # only place the set — and therefore the address — is named.
                status, adv_handle, connection = struct.unpack_from("<BBH", params, 1)
                address = (self.addresses[adv_handle]
                           if adv_handle < len(self.addresses) else "?")
                self._last_set_address = address
                if connection in self.links:
                    self.links[connection].address = address
                _LOG.info("connection on advertising set %d = %s (status 0x%02x)",
                          adv_handle, address, status)
        elif code == EV_DISCONN_COMPLETE:
            handle = struct.unpack_from("<H", params, 1)[0]
            link = self.links.pop(handle, None)
            if link is not None:
                _LOG.info("disconnected handle=%d reason=0x%02x address=%s summary=%s",
                          handle, params[3], link.address, link.protocol.session_summary())
            self._rearm()
        elif code == EV_NUM_COMPLETED_PACKETS and params and self.writer is not None:
            for index in range(params[0]):
                _handle, count = struct.unpack_from("<HH", params, 1 + index * 4)
                self.writer.completed(count)
