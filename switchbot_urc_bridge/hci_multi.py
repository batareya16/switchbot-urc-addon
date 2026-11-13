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
from collections import deque
from functools import wraps
import logging
import math
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
OP_LE_CREATE_CONN = 0x200D
OP_LE_CREATE_CONN_CANCEL = 0x200E
OP_DISCONNECT = 0x0406
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
        return self._receive(timeout)

    def _receive(self, timeout: float):
        """Read the wire without replaying packets deferred by a command."""
        if timeout <= 0:
            return None
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return None
        packet = self.sock.recv(2048)
        return (packet[0], packet[1:]) if len(packet) >= 2 else None

    def command(self, opcode: int, payload: bytes = b"", timeout: float = 3.0) -> bytes:
        self.sock.send(
            bytes([HCI_COMMAND_PKT]) + struct.pack("<HB", opcode, len(payload)) + payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            packet = self._receive(deadline - time.monotonic())
            if packet is None:
                continue
            kind, body = packet
            if kind == HCI_EVENT_PKT and len(body) >= 2:
                code, params = body[0], body[2:2 + body[1]]
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
            # Connection, disconnection, credits and ATT must reach the main loop, including
            # when they arrive before the command's reply. Never read this queue here again.
            self.spare.append(packet)
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
        self.outstanding: dict[int, int] = {}
        self.pending: deque[tuple[int, int, bytes]] = deque()

    @property
    def inflight(self) -> int:
        return sum(self.outstanding.values())

    def completed(self, handle: int, count: int) -> None:
        remaining = max(0, self.outstanding.get(handle, 0) - count)
        if remaining:
            self.outstanding[handle] = remaining
        else:
            self.outstanding.pop(handle, None)
        self._flush()

    def disconnected(self, handle: int) -> None:
        # The controller frees this connection's buffers on disconnect. A completion event
        # need not follow. Queued fragments must never reach a later reuse of the handle.
        self.outstanding.pop(handle, None)
        self.pending = deque(item for item in self.pending if item[0] != handle)
        self._flush()

    def send(self, handle: int, data: bytes) -> None:
        frame = struct.pack("<HH", len(data), ATT_CID) + data
        fragments = (len(frame) + self.payload_size - 1) // self.payload_size
        if len(self.pending) + fragments > 512:
            raise BufferError("ACL output queue is full")
        boundary = PB_FIRST
        while frame:
            chunk, frame = frame[:self.payload_size], frame[self.payload_size:]
            self.pending.append((handle, boundary, chunk))
            boundary = PB_CONTINUE
        self._flush()

    def _flush(self) -> None:
        # Do not read HCI here: the event loop must keep serving every connection even while
        # one connection has used all controller buffers.
        while self.pending and self.inflight < self.credits:
            handle, boundary, chunk = self.pending[0]
            self.channel.sock.send(
                bytes([HCI_ACL_PKT])
                + struct.pack("<HH", handle | (boundary << 12), len(chunk)) + chunk)
            self.pending.popleft()
            self.outstanding[handle] = self.outstanding.get(handle, 0) + 1


class AttManagementClient:
    """ATT client for WoRWS reads and encrypted management transactions.

    One worker makes requests; the HCI loop delivers responses and keeps serving presses.
    GATT handles are discovered afresh for each connection; crypto uses the session IV.
    """
    WRITE_UUID = bytes.fromhex("cba20002224d11e69fb80002a5d5c51b")[::-1]
    NOTIFY_UUID = bytes.fromhex("cba20003224d11e69fb80002a5d5c51b")[::-1]

    def __init__(self, peer: str, send: Callable) -> None:
        self.peer = peer
        self.send = send
        self.handle: int | None = None
        self.connected = threading.Event()
        self.closed = threading.Event()
        self.condition = threading.Condition()
        self.replies: deque[bytes] = deque()
        self.notifications: deque[tuple[int, bytes]] = deque()
        self.error = ""
        self.closing = False
        self.stage = "connect"
        self.prepared = False
        self.mtu = 23
        self.write_handle = 0
        self.notify_handle = 0
        self.write_properties = 0
        self.iv = b""
        self.responses: list[str] = []
        self.command_started = False

    def fail(self, error: str, *, disconnected: bool = False) -> None:
        with self.condition:
            self.error = error
            self.connected.set()
            if disconnected:
                self.closed.set()
            self.condition.notify_all()

    def handle_pdu(self, pdu: bytes) -> bytes | None:
        if not pdu:
            return None
        if pdu[0] == 0x02 and len(pdu) == 3:
            return b"\x03\x00\x02"  # answer the peer's concurrent MTU exchange
        with self.condition:
            if pdu[0] in (0x1B, 0x1D) and len(pdu) >= 3:
                self.notifications.append((struct.unpack_from("<H", pdu, 1)[0], pdu[3:]))
                if len(self.notifications) > 64:
                    self.notifications.popleft()
            else:
                if len(self.replies) >= 64:
                    self.fail("too many unsolicited ATT responses")
                    return None
                self.replies.append(pdu)
            self.condition.notify_all()
        return b"\x1e" if pdu[0] == 0x1D else None

    def _wait(self, queue, timeout: float):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if self.error:
                    raise ConnectionError(self.error)
                if queue:
                    return queue.popleft()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"raw HCI management timed out at {self.stage}")
                self.condition.wait(remaining)

    def request(self, pdu: bytes, response_opcode: int) -> bytes:
        self.send(pdu)
        reply = self._wait(self.replies, 5.0)
        if reply[0] == 0x01:
            if len(reply) == 5 and reply[1] == pdu[0] and reply[4] == 0x0A:
                return b""  # end of discovery range
            raise RuntimeError(f"raw ATT request {pdu[0]:02x} rejected: {reply.hex()}")
        if reply[0] != response_opcode:
            raise RuntimeError(f"unexpected raw ATT response: {reply.hex()}")
        return reply

    def prepare(self) -> None:
        if self.prepared:
            return
        self.stage = "mtu"
        mtu = self.request(b"\x02\x00\x02", 0x03)
        if len(mtu) != 3 or struct.unpack_from("<H", mtu, 1)[0] < 23:
            raise RuntimeError("invalid ATT MTU response")
        self.mtu = min(512, struct.unpack_from("<H", mtu, 1)[0])
        self.stage = "characteristic_discovery"
        declarations = []
        start = 1
        while start <= 0xFFFF:
            reply = self.request(struct.pack("<BHHH", 0x08, start, 0xFFFF, 0x2803), 0x09)
            if not reply:
                break
            if len(reply) <= 2 or reply[1] not in (7, 21) or (len(reply) - 2) % reply[1]:
                raise RuntimeError("invalid ATT characteristic discovery response")
            last = start - 1
            for off in range(2, len(reply), reply[1]):
                record = reply[off:off + reply[1]]
                declaration, props, value = struct.unpack_from("<HBH", record)
                if declaration <= last or value <= declaration:
                    raise RuntimeError("non-progressing ATT characteristic discovery")
                declarations.append((declaration, props, value, record[5:]))
                last = declaration
            start = last + 1
        write = next((row for row in declarations if row[3] == self.WRITE_UUID), None)
        notify = next((row for row in declarations if row[3] == self.NOTIFY_UUID), None)
        if write is None or notify is None or not write[1] & 0x08 or not notify[1] & 0x10:
            raise RuntimeError("WoRWS management characteristics were not discovered")
        self.stage = "descriptor_discovery"
        end = next((row[0] - 1 for row in declarations if row[0] > notify[0]), 0xFFFF)
        start = notify[2] + 1
        cccd = None
        while start <= end:
            reply = self.request(struct.pack("<BHH", 0x04, start, end), 0x05)
            if not reply:
                break
            if len(reply) < 2 or reply[1] not in (1, 2):
                raise RuntimeError("invalid ATT descriptor discovery response")
            size = 4 if reply[1] == 1 else 18
            if len(reply) <= 2 or (len(reply) - 2) % size:
                raise RuntimeError("invalid ATT descriptor discovery length")
            last = start - 1
            for off in range(2, len(reply), size):
                handle = struct.unpack_from("<H", reply, off)[0]
                if handle <= last or handle > end:
                    raise RuntimeError("non-progressing ATT descriptor discovery")
                if size == 4 and reply[off + 2:off + 4] == b"\x02\x29":
                    cccd = handle
                last = handle
            if cccd is not None:
                break
            start = last + 1
        if cccd is None:
            raise RuntimeError("WoRWS notification descriptor was not discovered")
        self.stage = "subscribe"
        if self.request(struct.pack("<BHH", 0x12, cccd, 1), 0x13) != b"\x13":
            raise RuntimeError("invalid ATT subscription response")
        self.write_handle, self.write_properties = write[2], write[1]
        self.notify_handle = notify[2]
        self.prepared = True

    def await_notification(self, match: Callable, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            source, data = self._wait(self.notifications, max(0, deadline - time.monotonic()))
            if source == self.notify_handle and match(data):
                return data
            if time.monotonic() >= deadline:
                raise TimeoutError(f"no WoRWS notification at {self.stage}")

    def write_frame(self, frame: bytes, *, response: bool = False) -> None:
        limit = self.mtu - 3
        if response:
            if len(frame) > limit or not self.write_properties & 0x08:
                raise RuntimeError("management frame cannot use ATT Write Request")
            if self.request(struct.pack("<BH", 0x12, self.write_handle) + frame, 0x13) != b"\x13":
                raise RuntimeError("invalid ATT management write response")
            return
        if not self.write_properties & 0x04:
            raise RuntimeError("WoRWS management requires write-without-response support")
        for off in range(0, len(frame), limit):
            self.send(struct.pack("<BH", 0x52, self.write_handle) + frame[off:off + limit])
            if off + limit < len(frame):
                # Let ACL credits and other connections progress between application chunks.
                if self.closed.wait(0.05):
                    raise ConnectionError(self.error or "management connection closed")

    def read_query(self, sub: int, timeout: float) -> bytes:
        self.stage = f"query_0F63{sub:02X}"
        with self.condition:
            self.notifications.clear()
        self.write_frame(bytes([0x57, 0, 0, 0, 0x0F, 0x63, sub]), response=True)
        return self.await_notification(
            lambda data: len(data) >= 8 and data[:4] == b"\x01\x00\x00\x00", timeout)

    def query(self, subcommands: list[tuple[int, float]]) -> list[str]:
        self.prepare()
        results = []
        for sub, timeout in subcommands:
            results.append(self.read_query(sub, timeout).hex())
        return results

    def execute_steps(self, key: bytes, key_id: int, steps: list[dict], crypt: Callable) -> dict:
        self.prepare()
        if not steps or any(step["kind"] == "command" for step in steps):
            self.stage = "handshake"
            with self.condition:
                self.notifications.clear()
            # Matches the working management path: get-random is a Write Command.
            self.write_frame(bytes([0x57, 0, 0, 0, 0x0F, 0x21, 0x03, key_id]))
            raw = self.await_notification(
                lambda data: len(data) in (4, 20) and data[1:4] == b"\x00\x00\x00"
                and data[0] in (1, 2, 4), 35.0)
            if len(raw) != 20 or raw[0] != 1:
                raise RuntimeError(f"WoRWS handshake rejected: code=0x{raw[0]:02x}")
            self.iv = raw[4:20]
        for index, step in enumerate(steps):
            timeout = float(step.get("timeout", 20.0))
            if step["kind"] == "query":
                self.responses.append(self.read_query(int(step["subcmd"]), timeout).hex())
                continue
            self.stage = f"command_{index + 1}"
            plaintext = bytes.fromhex(step["plaintext"])
            frame = bytes([0x57, key_id]) + self.iv[:2] + crypt(key, self.iv, plaintext)
            with self.condition:
                self.notifications.clear()
            # Once any mutation may have reached the controller, never call a later error a
            # handshake/connect failure: the integration may retry those automatically.
            self.command_started = True
            self.write_frame(frame)

            def decode(raw: bytes) -> bytes:
                if len(raw) < 4 or raw[1] != key_id or raw[2:4] != self.iv[:2]:
                    return b""
                return raw[:1] if len(raw) == 4 else crypt(key, self.iv, raw[4:])

            def matches(raw: bytes) -> bool:
                decoded = decode(raw)
                if not decoded:
                    return False
                status = (len(decoded) == 16 and decoded[1] in (0x2D, 0x30)
                          and decoded[0] not in {0, 1, 2, 4, 5, 0x10, 0x11})
                return plaintext == b"\x02" or not status

            raw = self.await_notification(matches, timeout)
            decoded = decode(raw)
            self.responses.append(decoded.hex())
            accepted = step.get("accepted_codes")
            if accepted is not None and decoded[0] not in accepted:
                raise RuntimeError(f"management step {index + 1} rejected: response={decoded.hex()}")
        return {"ok": True, "iv": self.iv.hex(), "responses": list(self.responses),
                "strict_accepted_codes": True, "transport": "raw_hci"}


def _controller_locked(method):
    """MQTT control and the event loop must never read the same socket concurrently."""
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._io_lock:
            return method(self, *args, **kwargs)
    return locked


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
        self._io_lock = threading.RLock()
        self._pending_set_addresses: dict[int, str] = {}
        self._central_client: AttManagementClient | None = None
        self._central_link: Link | None = None
        self._management_lock = threading.Lock()

    # -- controller ownership ------------------------------------------------------------

    @_controller_locked
    def _claim(self) -> None:
        outcome = set_powered(self.index, False)
        if outcome != "ok":
            raise RuntimeError(f"could not power {self.adapter} down: {outcome}")
        try:
            self.channel = UserChannel(self.index)
            self._initialise_controller(self.channel)
        except Exception:
            self._release()
            raise

    def _initialise_controller(self, channel: UserChannel) -> None:
        channel.command(OP_RESET)
        channel.command(OP_SET_EVENT_MASK, bytes.fromhex("ffffffffffffff3f"))
        channel.command(OP_LE_SET_EVENT_MASK, LE_EVENT_MASK)
        self.own_public = ":".join(
            f"{byte:02X}" for byte in reversed(channel.command(OP_READ_BD_ADDR)[:6]))
        _LOG.info("%s is the controller at %s", self.adapter, self.own_public)
        if self.expected_address and normalise(self.expected_address) != normalise(self.own_public):
            # sysfs and the controller disagree, so something renumbered under us mid-start.
            raise RuntimeError(
                f"{self.adapter} reports {self.own_public} but was expected to be "
                f"{self.expected_address}; set the adapter option to a MAC rather than hciN"
            )
        payload_size, credits = self._buffer_size(channel)

        try:
            available = channel.command(OP_LE_READ_ADV_SETS)[0]
        except HciCommandError as err:
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

    @_controller_locked
    def _release(self) -> None:
        if self._central_client is not None:
            self._central_client.fail("controller released", disconnected=True)
            self._central_client = None
        self._central_link = None
        if self.channel is not None:
            try:
                self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]), timeout=1.0)
            except (OSError, TimeoutError):
                pass
            self.channel.close()
            self.channel = None
        self.writer = None
        self.links.clear()
        self._pending_set_addresses.clear()
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
            "raw_management": True,
        }

    @_controller_locked
    def set_addresses(self, addresses: list[str]) -> list[str]:
        """Serve a different set of addresses, without restarting the add-on.

        The controller is reconfigured in place: an advertising set cannot change its address
        while it is enabled, so this stops advertising, rewrites every set, and starts again.
        Live connections are left alone — they are already past advertising.
        """
        if any(not is_address(item) for item in addresses):
            raise ValueError("every target must be a six-byte Bluetooth address")
        wanted = list(dict.fromkeys(format_address(item) for item in addresses))
        if any(normalise(item) != normalise(self.own_public)
               and (address_bytes(item)[5] & 0xC0) != 0xC0 for item in wanted):
            raise ValueError("virtual targets must use static random addresses (C0–FF first octet)")
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
        # A connection may have arrived while an HCI command was being acknowledged. Apply
        # its deferred events before deciding which advertising sets are safe to change.
        while self.channel.spare:
            self._serve_once()
        for link in self.links.values():
            if link.address not in self.addresses:
                raise RuntimeError("cannot change targets before a live connection is identified")
            slot = self.addresses.index(link.address)
            if slot >= len(wanted) or wanted[slot] != link.address:
                raise RuntimeError("cannot remove or reorder a connected target; try when idle")
        self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]))
        previous = self.addresses
        self.addresses = wanted
        try:
            for handle, address in enumerate(wanted):
                if handle >= len(previous) or address != previous[handle]:
                    self._configure_set(handle, address)
            self._rebuild_enable_frame()
            self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
        except (OSError, TimeoutError):
            # Put the working set back rather than leaving the bridge advertising nothing.
            self.addresses = previous
            for handle, address in enumerate(previous):
                if handle >= len(wanted) or address != wanted[handle]:
                    self._configure_set(handle, address)
            self._rebuild_enable_frame()
            self.channel.command(OP_LE_SET_EXT_ADV_ENABLE, self._enable_frame)
            raise
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

    @_controller_locked
    def pause(self) -> bool:
        """Hand the controller back so the integration can run a management session on it."""
        if self._paused.is_set():
            _LOG.info("multi-address bridge already paused; no-op")
            return True
        self._paused.set()
        self._release()
        _LOG.info("multi-address bridge paused; %s is BlueZ's again", self.adapter)
        return True

    @_controller_locked
    def resume(self) -> bool:
        if not self._paused.is_set():
            _LOG.info("multi-address bridge already running; resume no-op")
            return True
        self._claim()
        self._paused.clear()
        _LOG.info("multi-address bridge resumed")
        return True

    def query_inventory(self, address: str, steps: list[dict]) -> dict:
        """Read via our central connection while continuing to serve peripheral connections.

        Convenience wrapper for an isolated unencrypted installed-device table read.
        """
        if not steps or any(step.get("kind") != "query" or int(step.get("subcmd", -1)) != 7
                            for step in steps):
            raise ValueError("raw HCI management supports only inventory query 0F6307")
        return self._run_management_session(
            address, lambda client: {"ok": True, "iv": "", "transport": "raw_hci",
                                     "responses": client.query([(7, float(step.get("timeout", 10)))
                                                                for step in steps])})

    def manage_remote(self, address: str, key_hex: str, key_id: int, steps: list[dict],
                      *, crypt: Callable) -> dict:
        """Run all management through raw HCI, without transport fallback or command retries."""
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 16 or type(key_id) is not int or not 0 <= key_id <= 255:
                raise ValueError("management requires a 16-byte key and a one-byte key ID")
            if not isinstance(steps, list):
                raise ValueError("management steps must be a list")
            # Validate the entire transaction before connecting, not after an earlier mutation.
            for step in steps:
                if not isinstance(step, dict) or step.get("kind") not in {"command", "query"}:
                    raise ValueError("invalid management step")
                timeout = float(step.get("timeout", 20))
                if not math.isfinite(timeout) or timeout <= 0:
                    raise ValueError("management timeout must be positive and finite")
                if step["kind"] == "query":
                    if type(step.get("subcmd")) is not int or not 0 <= step["subcmd"] <= 255:
                        raise ValueError("query subcommand must be a byte")
                else:
                    if not bytes.fromhex(step["plaintext"]):
                        raise ValueError("management plaintext must not be empty")
                    codes = step.get("accepted_codes")
                    if codes is not None and (not isinstance(codes, list) or not codes or any(
                        type(code) is not int or not 0 <= code <= 255 for code in codes
                    )):
                        raise ValueError("accepted_codes must be a nonempty list of bytes")
            address_bytes(address)
        except (ValueError, TypeError, KeyError) as err:
            return {"ok": False, "failed_stage": "validation", "error": str(err),
                    "responses": [], "iv": "", "transport": "raw_hci"}
        return self._run_management_session(
            address, lambda client: client.execute_steps(key, key_id, steps, crypt),
            report_errors=True)

    def _run_management_session(self, address: str, operation: Callable,
                                *, report_errors: bool = False) -> dict:
        peer = format_address(address)
        address_bytes(peer)
        with self._management_lock:
            client = AttManagementClient(peer, lambda pdu: self._central_send(client, pdu))
            initiated = False
            result = None
            failure = None
            try:
                with self._io_lock:
                    if self.channel is None or self._paused.is_set():
                        raise RuntimeError("raw HCI bridge is not running")
                    if self._central_client is not None or self._central_link is not None:
                        raise RuntimeError("previous raw HCI management connection is still closing")
                    self._central_client = client
                with self._io_lock:
                    # BlueZ lib/bluetooth/hci.h: 25-byte le_create_connection_cp.
                    initiated = True
                    try:
                        self.channel.command(OP_LE_CREATE_CONN, struct.pack(
                            "<HHBB6sBHHHHHH", 0x0060, 0x0030, 0, 0, address_bytes(peer), 0,
                            self.conn_min, self.conn_max, 0, 400, 0, 0))
                    except HciCommandError:
                        initiated = False
                        raise
                if not client.connected.wait(8.0):
                    raise TimeoutError("raw HCI management connection timed out")
                if client.error:
                    raise ConnectionError(client.error)
                result = operation(client)
            except Exception as err:
                failure = err
            finally:
                # A refused request must not close an older session still owned by the bridge.
                if self._central_client is client:
                    try:
                        self._close_management(client, initiated)
                    except Exception as err:
                        failure = RuntimeError(f"{failure}; cleanup: {err}") if failure else err
            if failure is not None:
                if not report_errors:
                    raise failure
                stage = ("command" if client.command_started else
                         "query" if client.stage.startswith("query_") else
                         "handshake" if client.stage == "handshake" else "connect")
                _LOG.warning("raw HCI management failed at %s: %s", client.stage, failure)
                return {"ok": False, "failed_stage": stage, "stage_detail": client.stage,
                        "error": str(failure), "iv": client.iv.hex(),
                        "responses": list(client.responses), "transport": "raw_hci",
                        "command_started": client.command_started,
                        "strict_accepted_codes": True}
            _LOG.info("raw HCI management complete; bridge stayed active")
            return result

    def _close_management(self, client: AttManagementClient, initiated: bool) -> None:
        client.closing = True
        try:
            with self._io_lock:
                if self.channel is not None and initiated and not client.closed.is_set():
                    if client.handle is None:
                        try:
                            self.channel.command(OP_LE_CREATE_CONN_CANCEL)
                        except HciCommandError:
                            pass  # completion may already be deferred in the HCI queue
            if initiated and client.handle is None and not client.closed.is_set():
                client.connected.wait(1.0)
            with self._io_lock:
                if (self.channel is not None and client.handle is not None
                        and not client.closed.is_set()):
                    self.channel.command(OP_DISCONNECT, struct.pack("<HB", client.handle, 0x13))
            # Keep the client registered until the disconnect/cancel event is delivered.
            # Otherwise a late successful central connection would be mistaken for a remote.
            if initiated and not client.closed.wait(3.0):
                raise TimeoutError("raw HCI management disconnect/cancel was not confirmed")
        finally:
            with self._io_lock:
                if self._central_client is client and (client.closed.is_set() or not initiated):
                    self._central_client = None

    @_controller_locked
    def _central_send(self, client: AttManagementClient, pdu: bytes) -> None:
        if (self.writer is None or self._central_client is not client
                or client.handle is None or client.closed.is_set() or client.error):
            raise ConnectionError("raw HCI management connection is closed")
        self.writer.send(client.handle, pdu)

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
        self.links[handle] = Link(
            handle, self._pending_set_addresses.pop(handle, "?"), protocol, device)
        _LOG.info("connected handle=%d peer=%s", handle, peer)
        # BlueZ used to start this exchange as the reverse GATT client; without it WoRWS
        # correctly refuses anything larger than the default ATT MTU of 23.
        self.writer.send(handle, b"\x02\x00\x02")

    def _serve(self) -> None:
        while not self._stop.is_set():
            with self._io_lock:
                self._serve_once()
            # Give waiting MQTT control calls a chance to acquire ownership between reads.
            self._stop.wait(0.001)

    def _serve_once(self) -> None:
        if self._paused.is_set() or self.channel is None:
            return
        try:
            packet = self.channel.read(0.1)
        except OSError as err:
            if not self._stop.is_set() and not self._paused.is_set():
                _LOG.warning("HCI read failed: %s", err)
            return
        if packet is None:
            return
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
        link = (self._central_link if self._central_link is not None
                and self._central_link.handle == handle else self.links.get(handle))
        if link is None or self.writer is None:
            return
        for pdu in link.feed(body[4:4 + length], boundary != PB_CONTINUE):
            response = (link.protocol.handle_pdu(pdu) if isinstance(link.protocol, AttManagementClient)
                        else link.protocol.handle(pdu))
            if response is not None:
                self.writer.send(handle, response)

    def _on_event(self, code: int, params: bytes) -> None:
        if code == EV_LE_META and params:
            subevent = params[0]
            if subevent in (LE_CONNECTION_COMPLETE, LE_ENHANCED_CONNECTION_COMPLETE):
                if params[1]:
                    if self._central_client is not None:
                        self._central_client.fail(f"central connection failed: 0x{params[1]:02x}",
                                                  disconnected=True)
                        if self._central_client.closing:
                            self._central_client = None
                    _LOG.warning("connection failed with status 0x%02x", params[1])
                    return
                handle = struct.unpack_from("<H", params, 2)[0]
                peer = ":".join(f"{b:02X}" for b in reversed(params[6:12]))
                if params[4] == 0:  # central role; never construct a peripheral device for it
                    client = self._central_client
                    if client is None or client.peer != peer:
                        _LOG.warning("closing unexpected central connection to %s", peer)
                        self.channel.command(OP_DISCONNECT, struct.pack("<HB", handle, 0x13))
                        return
                    client.handle = handle
                    self._central_link = Link(handle, peer, client, None)
                    client.connected.set()
                    if client.closing:
                        self.channel.command(OP_DISCONNECT, struct.pack("<HB", handle, 0x13))
                        return
                    _LOG.info("raw HCI management connected handle=%d peer=%s", handle, peer)
                    return
                self._open_link(handle, peer)
            elif subevent == LE_ADV_SET_TERMINATED:
                # This arrives around the connection event, in no guaranteed order, and is the
                # only place the set — and therefore the address — is named.
                status, adv_handle, connection = struct.unpack_from("<BBH", params, 1)
                address = (self.addresses[adv_handle]
                           if adv_handle < len(self.addresses) else "?")
                if status or connection == 0xFFFF:
                    _LOG.warning("advertising set %d ended without a connection (status 0x%02x)",
                                 adv_handle, status)
                    return
                if connection in self.links:
                    self.links[connection].address = address
                else:
                    self._pending_set_addresses[connection] = address
                _LOG.info("connection on advertising set %d = %s (status 0x%02x)",
                          adv_handle, address, status)
        elif code == EV_DISCONN_COMPLETE:
            handle = struct.unpack_from("<H", params, 1)[0]
            if self._central_link is not None and self._central_link.handle == handle:
                client = self._central_link.protocol
                client.fail(f"central disconnected: 0x{params[3]:02x}", disconnected=True)
                if client.closing and self._central_client is client:
                    self._central_client = None
                self._central_link = None
            link = self.links.pop(handle, None)
            pending_address = self._pending_set_addresses.pop(handle, None)
            if self.writer is not None:
                self.writer.disconnected(handle)
            if link is not None:
                _LOG.info("disconnected handle=%d reason=0x%02x address=%s summary=%s",
                          handle, params[3], link.address, link.protocol.session_summary())
            # Only an incoming connection consumes one of our advertising sets. An outgoing
            # central management connection leaves those sets enabled, so re-enabling them here
            # sends an invalid 0x2039 command and can disturb the controller's active state.
            if link is not None or pending_address is not None:
                self._rearm()
        elif code == EV_NUM_COMPLETED_PACKETS and params and self.writer is not None:
            for index in range(params[0]):
                handle, count = struct.unpack_from("<HH", params, 1 + index * 4)
                self.writer.completed(handle, count)
