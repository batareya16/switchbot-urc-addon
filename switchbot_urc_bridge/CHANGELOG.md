# Changelog

## 0.53.5

- The add-on now answers the remote's connection requests the way a phone does. When the remote asks to change the connection parameters (an L2CAP update request, or the link-layer request the controller hands to the host), the add-on accepts it; before, every non-ATT frame from the remote was ignored, which may be what made the remote stop answering when it entered synchronisation mode.
- The log shows what the remote sends besides ATT data during a management session (L2CAP frames and connection, packet length and PHY updates), to find out why an install stalls.

## 0.53.4

- Fixed the connection to the remote dropping in the middle of an IR remote install (`central disconnected: 0x08`). The remote stops answering the radio for several seconds while it stores the transferred code, and the 4 second link timeout ended the connection. The link timeout is now 20 seconds, the same as the official app uses.
- The log now shows how long the remote took to answer each install step.

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
