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
                            raise OSError(
                                f"command 0x{opcode:04x} failed with status 0x{params[3]:02x}")
                        return params[4:]
                elif code == EV_CMD_STATUS:
                    status, _count, returned = struct.unpack_from("<BBH", params)
                    if returned == opcode:
                        if status:
                            raise OSError(
                                f"command 0x{opcode:04x} failed with status 0x{status:02x}")
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
        self.adapter = adapter
        self.index = int(adapter.removeprefix("hci"))
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
        payload_size, credits = self._buffer_size(channel)
        available = channel.command(OP_LE_READ_ADV_SETS)[0]
        if len(self.addresses) > available:
            channel.close()
            set_powered(self.index, True)
            raise RuntimeError(
                f"{self.adapter} offers {available} advertising sets but "
                f"{len(self.addresses)} addresses were configured"
            )
        self.channel = channel
        self.writer = AclWriter(channel, payload_size, credits)
        for handle, address in enumerate(self.addresses):
            self._configure_set(handle, address)
        frame = bytes([0x01, len(self.addresses)])
        for handle in range(len(self.addresses)):
            frame += struct.pack("<BHB", handle, 0, 0)
        self._enable_frame = frame
        channel.command(OP_LE_SET_EXT_ADV_ENABLE, frame)
        _LOG.info("%s claimed: public %s, ACL payload %d B, %d buffers, serving %s",
                  self.adapter, self.own_public, payload_size, credits,
                  ", ".join(self.addresses))

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
        payload = channel.command(OP_LE_READ_BUFFER_SIZE)
        length, count = struct.unpack_from("<HB", payload)
        if length and count:
            return length, count
        payload = channel.command(OP_READ_BUFFER_SIZE)
        acl_length, _sco, acl_count, _sco_count = struct.unpack_from("<HBHH", payload)
        return acl_length, acl_count

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
