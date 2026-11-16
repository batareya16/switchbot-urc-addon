# Set up SwitchBot URC Bridge

The Bridge connects your physical SwitchBot Universal Remote (WoRWS) to Home Assistant so its buttons can run actions you choose in Remote Studio.

## What you need

- **Home Assistant OS** with the [SwitchBot Universal Remote integration](https://github.com/batareya16/SwitchbotURCHass) set up. Open **Remote Studio** from the sidebar using an administrator account.
- The **Mosquitto broker** app running and the **MQTT** integration set up in **Settings → Devices & services**. [MQTT setup](https://www.home-assistant.io/integrations/mqtt/)
- A **dedicated Linux-compatible Bluetooth 5.0 or newer USB dongle** with BLE peripheral mode and **connectable LE Extended Advertising**. Confirm those features with the seller or in the chipset specs before buying. For several Bridge remotes on one dongle, look for support for multiple connectable advertising sets. [Bluetooth LE features](https://www.bluetooth.com/bluetooth-le-primer/)

## Install and start

1. Add the repository to Home Assistant. In **Settings → Apps → Install app → ⋮ → Repositories**, add `https://github.com/batareya16/switchbot-urc-addon`. Older versions call this the **Add-on Store**. Install **SwitchBot URC Bridge**.
2. Plug in the dedicated dongle. In **Settings → Connectivity → Bluetooth → Adapters**, note its Bluetooth address and disable Home Assistant's use of **that dongle**. Keep the dongle plugged in and leave your regular adapter enabled. The Bridge needs direct access to its dongle to receive connections from the remote. [Find your Bluetooth adapters](https://www.home-assistant.io/connectivity/bluetooth/#viewing-your-bluetooth-adapters-and-proxies)
3. In the Bridge's **Configuration** tab, set **Bluetooth adapter** (`adapter`) to that address. For a new setup, replace **Bridge device key** (`device_key`) with a private random value of 32 characters using only `0–9` and `a–f`. If you already use the Bridge, keep your existing key so your remotes can still connect.
4. Leave **Addresses (optional)** empty for automatic setup. Save, start the Bridge and enable **Start on boot**. The **Log** tab should show `multi-address bridge running`.

## Add your first remote

1. Wake up the physical Universal Remote and open **Remote Studio → Add a remote → Bridge remote**.
2. Pick a type, enter a name and choose **Install**. Leave **Bridge options** on **Automatic**. If Studio asks for the **Bridge device key**, paste the same key you saved in the Bridge.
3. Use **Quick bind** to control a light, or choose a button and add **Custom actions**. Click **Save**. Open the new remote on the physical WoRWS and press a button.

To add another Bridge remote, repeat step 1. Studio chooses a free address automatically. It shows available capacity under **Native remotes available**. The exact number depends on the dongle and the Bridge addresses already in use. Automatically assigned addresses persist across restarts. If you replace the dongle or change the address list, remotes bound to addresses that are no longer served need to be moved to an active address in Studio.

## Configuration reference

For a new setup, fill in **Bluetooth adapter** and **Bridge device key**. Leave the other fields at their defaults. If you use **Edit in YAML**, this is what a complete configuration looks like:

```yaml
adapter: "02:11:22:33:44:55"
device_key: "f1a09c4b7d2e658301be4d96c8a72f50"
addresses: ""
remote_address: ""
mqtt_topic: "switchbot_urc/button"
discovery: true
hci_trace: false
conn_interval_min_ms: 7.5
conn_interval_max_ms: 15.0
```

Replace the example adapter address with your dongle's Bluetooth address. The example key is public. Generate your own with a password manager set to generate 32 characters from `0123456789abcdef`, or run `openssl rand -hex 16` in a terminal. Paste the resulting key into the Bridge and into Remote Studio when prompted.

| Setting | What it does |
| --- | --- |
| **Bluetooth adapter** (`adapter`) | Enter the address of the dedicated dongle as six colon-separated pairs, for example `02:11:22:33:44:55`. A name such as `hci1` also works, but can change after a restart or replug. |
| **Bridge device key** (`device_key`) | Enter 32 hexadecimal characters as one string, without spaces. Use the same key in Remote Studio. |
| **Addresses (optional)** (`addresses`) | Leave blank in the form or use `""` in YAML for automatic allocation. To prioritize specific addresses, enter one comma-separated string such as `C0:12:34:56:78:90, C1:12:34:56:78:90`. Each new custom virtual address must start with `C0`–`FF`. |
| **Universal Remote address (optional)** (`remote_address`) | Leave blank in the form or use `""` in YAML for a standard install. For diagnostics, enter the Bluetooth address of the physical remote, for example `02:66:77:88:99:AA`. Find it on the Universal Remote's integration page in Home Assistant. |
| **MQTT button topic** (`mqtt_topic`) | Keep `switchbot_urc/button` so Remote Studio receives button events. |
| **MQTT discovery** (`discovery`) | Leave on (`true`) to create the MQTT button event entity and device triggers in Home Assistant. |
| **Bluetooth trace logging** (`hci_trace`) | Leave off (`false`) for normal use. Turn on temporarily to collect a detailed Bluetooth log. |
| **Minimum and maximum connection interval** (`conn_interval_min_ms`, `conn_interval_max_ms`) | Keep `7.5` and `15.0` for normal use. Enter numbers in milliseconds, with a decimal point and no unit suffix. The physical remote chooses the actual interval. |

## If something doesn't work

| What you see | What to check |
| --- | --- |
| Bridge won't start or reports no extended advertising support | Confirm `adapter` points to the dedicated dongle and check that the dongle supports connectable LE Extended Advertising. |
| Studio can't find a Bridge | Check that the Bridge is running and that its log shows a connection to the MQTT broker. Confirm the MQTT integration is set up in Home Assistant. |
| A button does nothing in Home Assistant | Open the matching Bridge remote on the WoRWS, check that the mapping is saved in Studio, and check the Bridge log for the press. If the dongle or address list changed, verify the remote is assigned to an active address. |

The app uses host networking and direct Bluetooth controller access to advertise and receive connections on the dedicated dongle. The hardware and networking permissions shown by Home Assistant support that access.

[Report an issue](https://github.com/batareya16/switchbot-urc-addon/issues) · [Apache License 2.0](https://github.com/batareya16/switchbot-urc-addon/blob/master/LICENSE)
