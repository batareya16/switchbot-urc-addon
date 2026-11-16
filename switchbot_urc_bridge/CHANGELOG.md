# Changelog

## 0.32.2

- Shows Linux adapter names such as `hci0` and `hci1` in setup examples.
- Clarifies that Refresh uses the remote address saved in the integration.

## 0.32.1

- Adds help for each field in the Configuration tab and a complete YAML example in Documentation.

## 0.32.0

- The Bridge automatically assigns and remembers addresses for each dongle.
- All controllers use the same direct Bluetooth transport. **Upgrading requires a dongle with connectable LE Extended Advertising.**

## 0.31.3

- Accepts queued button presses after reconnecting and avoids delivering duplicate events to Home Assistant.

## 0.31.2

- Retries transient management connection failures before writing a command.

## 0.31.0

- Runs management and button handling through the same controller for multi-address bridges.
- Improves handling of concurrent connections and makes management failures easier to identify.
