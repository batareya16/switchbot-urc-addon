# Changelog

## 0.53.2

- The remote often refuses the first one or two connection attempts; this is routine, so a refused attempt is now logged at info level and the add-on tries up to six times before it reports a failure.
- Large uploads to the remote no longer pause 50 ms after every chunk, and the log shows how long such an upload took and which ATT MTU the remote granted.

## 0.52.2

- Align the Bridge add-on version with integration release 0.52.2.

## 0.52.1

- Align the Bridge add-on version with integration release 0.52.1.

## 0.52.0

- Align the Bridge add-on version with integration release 0.52.0.

## 0.51.4

- Align the Bridge add-on version with integration release 0.51.4.

## 0.51.3

- Align the Bridge add-on version with the integration release.

## 0.32.5

- Reassemble fragmented scene list replies for Remote Studio.

## 0.32.4

- Receive open button commands and remove the Bridge device key option.

## 0.32.3

- Simplifies the setup guide for adding Bridge remotes from Remote Studio.

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
