# SwitchBot URC Bridge (Home Assistant add-on)

Fake native SwitchBot target for WoRWS. Companion to the
[SwitchBot Universal Remote integration](https://github.com/batareya16/SwitchbotURCHass),
whose `PROTOCOL.md` documents the protocol this add-on speaks.

### 0.31.3 — recover queued encrypted presses after reconnects

The raw HCI bridge retains issued session IVs for 60 seconds per fake-target address.
A queued encrypted press from an earlier connection can be decrypted and acknowledged
in its original session. An already delivered frame receives another acknowledgement
without publishing a duplicate Home Assistant event. History is bounded, kept in memory,
and cleared when the add-on restarts. Frames that no retained IV can decrypt are ignored.

### 0.31.2 — recover transient native management connection failures

The management initiator scans continuously during the short-lived connection attempt.
Transient controller connection-failed (`0x3e`), link-timeout (`0x08`), and
connection-wait timeout failures are retried up to three times with a short backoff.
Retries stop when the management command write starts, so a mutation is never repeated
because its acknowledgement was lost.

### 0.31.0 — all multi-address management through raw HCI

HCI commands now preserve interleaved connection events and button packets. ACL replies queue
until controller buffers are available, with credits tracked per connection and reclaimed on
disconnect. Controller ownership changes are serialized with packet processing. Connections
are matched to their advertising address by handle, and adding a target leaves unchanged
connected advertising sets configured as they were. Failed startup returns the adapter to
BlueZ. These fixes have regression tests; radio behaviour still needs validation on hardware.

The multi-address bridge executes the entire management transaction through its own HCI/ATT
client: inventory/storage/scene reads, session handshake, target keys, binding pages, deleting,
renaming and other encrypted commands sent by the integration. It discovers fresh handles,
negotiates MTU, subscribes to notifications and chunks large frames to fit that MTU. Read-only
transactions skip the handshake; mixed transactions share one secure session. The adapter is
not handed to BlueZ and there is no automatic transport fallback.

Success logs `raw HCI management complete; bridge stayed active`. Failures report the failing
stage and completed responses to Home Assistant. Device rejection stops transactions that
specify accepted response codes. The bridge never automatically repeats a command after a lost
acknowledgement. Protocol errors do not count as physical disconnects: a new management
connection waits for confirmed cleanup of the old one.

Since 0.32, the add-on uses raw HCI for every controller. Startup requires a controller with
extended advertising support.

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
  integration; use a dedicated adapter with extended advertising for this add-on. Disable the
  dedicated adapter in Home Assistant's Bluetooth adapter settings.
- Set `adapter` to the controller's **MAC address** rather than `hciN` where you can. Kernel
  numbering is not stable — a reboot or a replug can swap hci0 and hci1, and the add-on then
  silently owns the wrong radio.

## Several native tiles on one adapter

Each native tile connects to one fixed BLE address, so several tiles need several addresses.
**There is nothing to configure.** Whether a controller can carry several addresses is a
property of the radio, so the add-on asks the kernel at startup and decides for itself:

- The add-on fills the controller's advertising sets at startup and reports the addresses it
  successfully enabled to Remote Studio. With a fresh configuration, the controller's own address
  is first and extra addresses are stable static random addresses. If the controller rejects the
  requested number of connectable sets, the bridge keeps the smaller pool it can enable.

Remote Studio assigns a free address during **Add a remote → Bridge remote**. Enter the add-on's
device key on first setup if Studio has no key saved for the bridge. **Bridge options** lets you
choose a particular free address.

**Addresses (optional)** is a comma-separated list of addresses to use first. The add-on keeps
previously served addresses across restarts and fills any remaining sets automatically. New
custom virtual addresses should be static random addresses with a first octet of `C0`–`FF`.
A tile already bound to an address needs that address to remain in the active pool.

Each add-on instance uses one Bluetooth adapter. To serve two adapters at once, run a separate
instance for each, with its own `adapter` setting and data directory. Each instance generates
its pool from its controller's address.

- The MQTT integration/broker.

## Install

1. Copy this folder to `/addons/switchbot_urc_bridge/` on the Home Assistant host.
2. Settings → Add-ons → Add-on Store → ⋮ → **Check for updates**.
3. Configure:
   - `adapter`: the dedicated dongle as `hci1` or a MAC such as `00:11:22:33:44:55`.
   - `remote_address`: physical WoRWS MAC, used for connection diagnostics.
   - `mqtt_topic`: defaults to `switchbot_urc/button`.
   - `discovery`: creates a Home Assistant MQTT event entity.
   - `hci_trace`: enable filtered advertising, connection and ATT logs when diagnosing.
   - `conn_interval_min_ms` / `conn_interval_max_ms`: the connection interval range advertised to
     the remote, in milliseconds (default `7.5`/`15.0`). The WoRWS central chooses the actual
     interval.
   - `device_key`: the same 16-byte key used by `bind_native` (32 hex characters).
4. Start the add-on and note the exact adapter MAC printed in its log.

If startup fails, the log identifies the configured adapter and reports the controller error.

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

At startup, look for `multi-address bridge running` and its list of active addresses.
On a press, look for `connected handle=`, `notify sub=True`, `REMOTE wrote` and the button
event. The disconnect summary includes `t_subscribe`, `t_write`, `t_ack` and `write_to_ack`.

Enable `hci_trace` to capture one ATT session. The `Disconnect Complete` block reports the
controller's reason. Verify that the saved target address appears in the active address list.

### Management sessions

Management uses the same raw HCI controller. Errors include `failed_stage`, `stage_detail`,
completed responses and whether a command may already have been written. The integration
verifies bind and delete results against the device table.

## License

Apache License 2.0 — see `LICENSE`.
