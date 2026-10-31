# SwitchBot URC Bridge (Home Assistant add-on)

Fake native SwitchBot target for WoRWS. Companion to the
[SwitchBot Universal Remote integration](https://github.com/batareya16/SwitchbotURCHass),
whose `PROTOCOL.md` documents the protocol this add-on speaks.

Firmware analysis confirms that a native button press makes
the remote connect directly to the MAC saved by `0F 20 08`, discover the standard SwitchBot GATT
profile, perform the `0F 21 03` session handshake, and write the encrypted device command.

## Disclaimer

This project is not affiliated with, endorsed by, or supported by SwitchBot. SwitchBot and
related names are trademarks of their respective owners.

It talks to the remote over an undocumented BLE protocol recovered by analysing the device's
own firmware and the vendor's app. Nothing here is sanctioned by the vendor: a firmware or app
update can break it at any time, and misuse can leave a remote in a state that needs
re-pairing. Use it at your own risk, on hardware you own.

## Why an add-on

The integration is a BLE **central** while configuring the remote. Receiving native presses needs
the opposite role, a connectable BLE **peripheral**, which Home Assistant integrations cannot
provide. The add-on owns the second adapter, exposes service `cba20d00` with write characteristic
`cba20002` and notify characteristic `cba20003`, decrypts commands, and forwards events by MQTT.

## Requirements

- A **second** Bluetooth adapter (USB dongle). One adapter stays with Home Assistant's Bluetooth
  integration; this add-on owns the other as a peripheral. Disable that adapter in Home
  Assistant's Bluetooth adapter settings; setting `diagnostic_scan: false` only disables this
  add-on's scanner, not another BlueZ client's scan.
- Set `adapter` to the controller's **MAC address** rather than `hciN` where you can. Kernel
  numbering is not stable — a reboot or a replug can swap hci0 and hci1, and the add-on then
  silently owns the wrong radio.

## Several native tiles on one adapter

Each native tile connects to one fixed BLE address, so several tiles need several addresses.
List them in `addresses` and the add-on serves all of them from one controller:

```yaml
adapter: "8A:88:1B:E0:1F:92"
addresses: "8A:88:1B:E0:1F:92, DA:71:16:E0:1F:92"
```

The first address should be the controller's own, so tiles already bound to it keep working;
every other must be a static random address, whose first octet is `C0` or higher.

This needs a Bluetooth 5 controller, because it uses one extended advertising set per address —
BlueZ cannot assign an address to an advertising instance, so the add-on takes the controller on
the HCI user channel and serves ACL, L2CAP and ATT itself. Leaving `addresses` empty keeps the
original BlueZ path, which serves one address and needs no Bluetooth 5.
- The MQTT integration/broker.

## Install

1. Copy this folder to `/addons/switchbot_urc_bridge/` on the Home Assistant host.
2. Settings → Add-ons → Add-on Store → ⋮ → **Check for updates**.
3. Configure:
   - `adapter`: the dedicated dongle as `hci1` or a MAC such as `00:11:22:33:44:55`.
   - `remote_address`: physical WoRWS MAC, used for connection diagnostics.
   - `name`: advertised name, for example `HASS Light`.
   - `mqtt_topic`: defaults to `switchbot_urc/button`.
   - `discovery`: creates a Home Assistant MQTT event entity.
   - `diagnostic_scan`: keep `false`. An active scan can interfere with connectable peripheral mode
     on some controllers; enable it only for advertisement capture.
   - `hci_trace`: keep `true` while diagnosing. It logs only advertising, connection/disconnection,
     and ATT packets; turn it off after button reception works.
   - `prewarm_remote_cache`: deprecated; set it to `false`. It remains accepted so existing add-on
     configurations continue to validate, but version 0.10.6 ignores it because BlueZ still runs
     reverse validation and delayed prewarm connections can block GATT-server registration.
   - `direct_att`: keep `true`. Version 0.11.0 uses a synchronous ATT server on the dedicated
     adapter to avoid WoRWS's two-second BlueZ discovery timeout. If the fixed ATT CID cannot be
     bound, the add-on logs the reason and automatically uses the D-Bus GATT server.
   - `raw_att_idle_timeout`: seconds a silent raw-ATT peer may hold the single connection slot
     before the add-on drops it (default `6.0`). WoRWS opens a fresh link per press and retries up
     to five times; a half-open link the kernel never reports as closed would otherwise wedge the
     server and make the next press wait. A real press completes in well under a second, so the
     default never interrupts one. Lower it only if consecutive presses still queue behind a stale
     link; raise it if a slow adapter drops healthy links. The per-press `t_subscribe`/`t_write`/
     `t_ack`/`write_to_ack` latencies now printed in each `raw ATT session summary` show the margin.
   - `raw_att_keepalive_interval` / `raw_att_keepalive_window`: after a real native command has
     been acknowledged, repeat that exact ACK every `1.0` second for at most `300.0` seconds. WoRWS
     firmware resets its bounded native-target transaction countdown whenever it processes the
     completion event; keeping the already-discovered link warm removes the multi-second discovery
     delay from the next press. No keepalive is sent before CCCD subscription or before the first
     real command, and it never publishes a duplicate Home Assistant event. Set either value to
     `0` to disable this experiment. Version 0.19.26 automatically migrates the former default
     `30.0`-second window to five minutes while preserving every custom value.
     Version 0.19.32 also waits for the kept-alive radio link to be fully released before a
     management handshake, so adding or editing a remote no longer races the warm connection.
   - `conn_interval_min_ms` / `conn_interval_max_ms`: the BLE connection interval range (in ms) the
     bridge requests — used for the adapter default, the per-remote kernel parameters, and the
     advertised AD type 0x12. Default `7.5`/`15.0`. The WoRWS central picks the actual interval, and
     on a slow CSR 4.0 link it may ignore this and run so slowly that native-press discovery barely
     fits its ~2 s deadline (first press lands, repeats stall at `descriptor-discovery`). Try a
     wider range such as `15.0`/`30.0` and compare the `t_subscribe`/`t_write` values in the `raw
     ATT session summary`: if they change, WoRWS honored it; if they are unchanged, the firmware is
     ignoring the range and a BLE 5.0 adapter (which negotiates a fast interval natively) is the real
     fix. Valid range 7.5–4000 ms; invalid values fall back to the default.
   - `device_key`: the same 16-byte key used by `bind_native` (32 hex characters).
4. Start the add-on and note the exact adapter MAC printed in its log.

The add-on fails instead of silently falling back to another adapter and never logs `device_key`.

## Bind the remote

Start the add-on first. In the integration options choose **Bind native target**, with `device_id`
equal to the printed adapter MAC and `target_key` equal to `device_key`. The integration sends key
setup (`0F 20 09`), target/MAC association (`0F 20 08`), and native page creation (`0F 62 06`).

## MQTT events

With discovery enabled, use `event.switchbot_urc_button`, or subscribe directly:

```yaml
automation:
  - trigger:
      platform: mqtt
      topic: switchbot_urc/button
    condition: "{{ trigger.payload_json.button == 'ON' }}"
    action:
      service: light.turn_on
      target: { entity_id: light.wiz_lamp }
```


## How the ATT server is laid out

The raw ATT server answers with one service and a six-handle database: write declaration and
value first, then notify declaration and value, then the CCCD. Every value handle sits inside the
declared service range. This order is what the firmware needs: it sends its queued handshake only
after a successful full-discovery callback, and putting the CCCD ahead of the notify declaration
stops the remote enabling notifications at all.

The remote writes plain target traffic such as `57 0F 49 01 01` with an ATT Write Command, which
has no ATT response, so completion has to come from the notify characteristic. The add-on
publishes the event and then notifies `01`, which is what the target protocol does; without it the
firmware requeues the same command up to five times.

The add-on also negotiates an ATT MTU of 512 right after accept. At the default MTU of 23 a
two-characteristic discovery response is silently discarded by the remote.

## Diagnostics

At startup, look for `active scanning is disabled`, `GATT application registered` and
`Advertisement registered`. The add-on advertises the full native discovery payload (`FD3D` device
type and the company `0x0969` MAC/status record) while keeping the 128-bit GATT UUID out of the
legacy packet so it does not overflow, and requests a 20 ms advertising interval — verify that
`HCI TRACE` reports `20.000 msec`.

On a press the expected sequence is `PERIPHERAL CONNECTED`, `notify sub=True`, `REMOTE wrote`,
then the decoded command and `native command ack -> 01`. If no peer state appears at all, check
that the MAC passed to `bind_native` exactly matches the adapter MAC printed by the add-on.

If a peer connects and immediately disconnects, leave `hci_trace: true` and copy the `HCI TRACE`
blocks for one press. The `Disconnect Complete` block carries the controller's reason, and the ATT
blocks show how far discovery got.

Each press prints a `raw ATT session summary` with `t_subscribe`, `t_write`, `t_ack` and
`write_to_ack`. Use those numbers rather than guesses when changing connection intervals: if they
do not move when you widen `conn_interval_min_ms`/`conn_interval_max_ms`, the firmware is ignoring
the request and only a BLE 5.0 adapter will help.

### When the system bus goes away

If `bluetoothd` or the system bus restarts under the add-on, python-dbus keeps dispatching
signals on a closed connection and bluezero's handler raises on every one of them. The log fills
with identical `org.freedesktop.DBus.Error.Disconnected` tracebacks and the bridge never serves
another press.

The add-on now detects that and exits, and `run.sh` restarts it after five seconds. A restart is
what actually recovers the service; staying up on a dead bus does not.

### Management sessions

Two failure modes were seen repeatedly during a long device session and are now handled.

BlueZ sometimes returns a GATT table **without** the SwitchBot characteristics (`cba20002` /
`cba20003`): the connect succeeds and the handshake then fails with
`Characteristic ... was not found`. The connect loop checks for both characteristics and treats
their absence as a failed attempt, so it clears the cached device and rediscovers instead of
aborting the session. After this change the same remote started answering a status poll with a
full 20-byte reply instead of a bare 4-byte envelope.

A session can also reject its **first** command with `04` even when that command is the one-byte
status poll that succeeds moments later. Codes from such a session say nothing about the command.
The integration retries the whole step list once with a fresh connection and handshake when the
first step comes back `04`; this is safe because `04` means the firmware rejected the command
without applying it, and no later step ran.

When reading a probe's result, send `02` as the first step and discard the run unless it answers
`01`. Several conclusions during that session were drawn from sessions that had already failed
this check and had to be withdrawn.

Repeated `RAW ATT CONNECTED` / `session summary ... subscribed=False device_writes=0` lines before
a delivered press are normal for this remote and bridge, and were observed for a tile that works.
They are not by themselves a sign of a broken profile.

## License

Apache License 2.0 — see `LICENSE`.
