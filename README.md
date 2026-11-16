# SwitchBot URC Bridge

Use a SwitchBot Universal Remote (WoRWS) to control Home Assistant lights, scenes, and scripts. This Home Assistant app receives button presses from Bridge remotes created in [Remote Studio](https://github.com/batareya16/SwitchbotURCHass).

[![Add the SwitchBot URC Bridge repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbatareya16%2Fswitchbot-urc-addon)

Before installing, check that you have **Home Assistant OS**, the **Mosquitto broker** app, and a **dedicated Bluetooth 5.0 or newer USB dongle that supports connectable LE Extended Advertising**. Keep your usual Bluetooth adapter available for Home Assistant.

After adding the repository, open **Settings → Apps**, install **SwitchBot URC Bridge**, and follow its **Documentation** tab. You can also read the [setup guide](switchbot_urc_bridge/DOCS.md) on GitHub.

If you only use your Universal Remote for infrared or Bluetooth keyboard (HID) control, install the integration and set up those remotes in Studio. The Bridge is needed for **Bridge remote** button actions in Home Assistant.

[Report an issue](https://github.com/batareya16/switchbot-urc-addon/issues) · [Apache License 2.0](LICENSE)
