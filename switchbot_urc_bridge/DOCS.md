# Set up SwitchBot URC Bridge

The Bridge connects your physical SwitchBot Universal Remote (WoRWS) to Home Assistant so its buttons can run actions you choose in Remote Studio.

## What you need

- **Home Assistant OS** with the [SwitchBot Universal Remote integration](https://github.com/batareya16/SwitchbotURCHass) set up. Open **Remote Studio** from the sidebar using an administrator account.
- The **Mosquitto broker** app running and the **MQTT** integration set up in **Settings → Devices & services**. [MQTT setup](https://www.home-assistant.io/integrations/mqtt/)
- A **dedicated Linux-compatible Bluetooth 5.0 or newer USB dongle** with BLE peripheral mode and **connectable LE Extended Advertising**. Confirm those features with the seller or in the chipset specs before buying. For several Bridge remotes on one dongle, look for support for multiple connectable advertising sets. [Bluetooth LE features](https://www.bluetooth.com/bluetooth-le-primer/)

## Install and start

1. Add the repository to Home Assistant. In **Settings → Apps → Install app → ⋮ → Repositories**, add `https://github.com/batareya16/switchbot-urc-addon`. Older versions call this the **Add-on Store**. Install **SwitchBot URC Bridge**.
2. Plug in the dedicated dongle. In **Settings → Connectivity → Bluetooth → Adapters**, note its Bluetooth address and disable Home Assistant's use of **that dongle**. Keep the dongle plugged in and leave your regular adapter enabled. The Bridge needs direct access to its dongle to receive connections from the remote. [Find your Bluetooth adapters](https://www.home-assistant.io/connectivity/bluetooth/#viewing-your-bluetooth-adapters-and-proxies)
3. In the Bridge's **Configuration** tab, set `adapter` to that Bluetooth address. For a new setup, replace `device_key` with a private random value of 32 characters using only `0–9` and `a–f`. If you already use the Bridge, keep your existing key so your remotes can still connect.
4. Leave **Addresses (optional)** empty for automatic setup. Save, start the Bridge and enable **Start on boot**. The **Log** tab should show `multi-address bridge running`.

## Add your first remote

1. Wake up the physical Universal Remote and open **Remote Studio → Add a remote → Bridge remote**.
2. Pick a type, enter a name and choose **Install**. Leave **Bridge options** on **Automatic**. If Studio asks for the **Bridge device key**, paste the same key you saved in the Bridge.
3. Use **Quick bind** to control a light, or choose a button and add **Custom actions**. Click **Save**. Open the new remote on the physical WoRWS and press a button.

To add another Bridge remote, repeat step 1. Studio chooses a free address automatically. It shows available capacity under **Native remotes available**. The exact number depends on the dongle and the Bridge addresses already in use. Automatically assigned addresses persist across restarts. If you replace the dongle or change the address list, remotes bound to addresses that are no longer served need to be moved to an active address in Studio.

## Configuration reference

| Setting | What it does |
| --- | --- |
| `adapter` | Bluetooth address of the dedicated dongle, for example `00:11:22:33:44:55`. A name such as `hci1` also works, but can change after a restart or replug. |
| `device_key` | The private 32-character hexadecimal key shared with Remote Studio. |
| `addresses` | Optional comma-separated addresses to use first. Leave empty for automatic setup. New custom virtual addresses must start with `C0`–`FF`. |
| `remote_address` | Optional Bluetooth address of the physical Universal Remote, used for diagnostics and to identify it to the integration. Leave blank for a standard install. |
| `mqtt_topic` | Topic for button events. Keep `switchbot_urc/button` for Remote Studio. |
| `discovery` | Publishes the MQTT button event entity and device triggers for Home Assistant when enabled. |
| `hci_trace` | Adds Bluetooth diagnostics to the log. Enable it when investigating a connection problem. |
| `conn_interval_min_ms`, `conn_interval_max_ms` | Advanced Bluetooth connection preferences. The defaults are `7.5` and `15.0` milliseconds. The physical remote negotiates the actual interval. |

## If something doesn't work

| What you see | What to check |
| --- | --- |
| Bridge won't start or reports no extended advertising support | Confirm `adapter` points to the dedicated dongle and check that the dongle supports connectable LE Extended Advertising. |
| Studio can't find a Bridge | Check that the Bridge is running and that its log shows a connection to the MQTT broker. Confirm the MQTT integration is set up in Home Assistant. |
| A button does nothing in Home Assistant | Open the matching Bridge remote on the WoRWS, check that the mapping is saved in Studio, and check the Bridge log for the press. If the dongle or address list changed, verify the remote is assigned to an active address. |

The app uses host networking and direct Bluetooth controller access to advertise and receive connections on the dedicated dongle. The hardware and networking permissions shown by Home Assistant support that access.

[Report an issue](https://github.com/batareya16/switchbot-urc-addon/issues) · [Apache License 2.0](https://github.com/batareya16/switchbot-urc-addon/blob/master/LICENSE)
