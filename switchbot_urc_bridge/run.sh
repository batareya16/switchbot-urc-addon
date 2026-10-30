#!/usr/bin/with-contenv bashio
# Read add-on options + MQTT service credentials, then launch the BLE-peripheral bridge.
set -e

ADAPTER="$(bashio::config 'adapter')"
REMOTE_ADDRESS="$(bashio::config 'remote_address')"
NAME="$(bashio::config 'name')"
TOPIC="$(bashio::config 'mqtt_topic')"
DISCOVERY="$(bashio::config 'discovery')"
DIAGNOSTIC_SCAN="$(bashio::config 'diagnostic_scan')"
HCI_TRACE="$(bashio::config 'hci_trace')"
PREWARM_REMOTE_CACHE="$(bashio::config 'prewarm_remote_cache')"
if bashio::config.has_value 'direct_att'; then
  DIRECT_ATT="$(bashio::config 'direct_att')"
else
  DIRECT_ATT="true"
fi
if bashio::config.has_value 'raw_att_idle_timeout'; then
  RAW_ATT_IDLE_TIMEOUT="$(bashio::config 'raw_att_idle_timeout')"
else
  RAW_ATT_IDLE_TIMEOUT="6.0"
fi
if bashio::config.has_value 'raw_att_keepalive_interval'; then
  RAW_ATT_KEEPALIVE_INTERVAL="$(bashio::config 'raw_att_keepalive_interval')"
else
  RAW_ATT_KEEPALIVE_INTERVAL="1.0"
fi
if bashio::config.has_value 'raw_att_keepalive_window'; then
  RAW_ATT_KEEPALIVE_WINDOW="$(bashio::config 'raw_att_keepalive_window')"
else
  RAW_ATT_KEEPALIVE_WINDOW="300.0"
fi
# Supervisor retains the old default after an add-on update. Migrate only the exact 0.19.25
# 30-second default; a value deliberately customized by the user remains untouched.
case "${RAW_ATT_KEEPALIVE_WINDOW}" in
  "30"|"30.0")
    RAW_ATT_KEEPALIVE_WINDOW="300.0"
    bashio::log.info "Migrated native ACK keepalive window from 30s to 300s"
    ;;
esac
if bashio::config.has_value 'conn_interval_min_ms'; then
  CONN_INTERVAL_MIN_MS="$(bashio::config 'conn_interval_min_ms')"
else
  CONN_INTERVAL_MIN_MS="7.5"
fi
if bashio::config.has_value 'conn_interval_max_ms'; then
  CONN_INTERVAL_MAX_MS="$(bashio::config 'conn_interval_max_ms')"
else
  CONN_INTERVAL_MAX_MS="15.0"
fi
# Supervisor preserves installed option values when config.yaml defaults change. Migrate only the
# exact former default pair; any genuinely custom interval remains untouched.
case "${CONN_INTERVAL_MIN_MS}:${CONN_INTERVAL_MAX_MS}" in
  "15:30"|"15:30.0"|"15.0:30"|"15.0:30.0")
    CONN_INTERVAL_MIN_MS="7.5"
    CONN_INTERVAL_MAX_MS="15.0"
    bashio::log.info "Migrated BLE connection interval from legacy 15-30ms to 7.5-15ms"
    ;;
esac
DEVICE_KEY="$(bashio::config 'device_key')"

if bashio::services.available "mqtt"; then
  export MQTT_HOST="$(bashio::services mqtt 'host')"
  export MQTT_PORT="$(bashio::services mqtt 'port')"
  export MQTT_USER="$(bashio::services mqtt 'username')"
  export MQTT_PASS="$(bashio::services mqtt 'password')"
  bashio::log.info "MQTT: ${MQTT_HOST}:${MQTT_PORT}"
else
  bashio::log.warning "No MQTT service — button events will only be logged."
fi

export ADAPTER REMOTE_ADDRESS NAME TOPIC DISCOVERY DIAGNOSTIC_SCAN HCI_TRACE \
  PREWARM_REMOTE_CACHE DEVICE_KEY
export DIRECT_ATT RAW_ATT_IDLE_TIMEOUT RAW_ATT_KEEPALIVE_INTERVAL \
  RAW_ATT_KEEPALIVE_WINDOW CONN_INTERVAL_MIN_MS CONN_INTERVAL_MAX_MS

bashio::log.info "Starting SwitchBot URC Bridge on adapter ${ADAPTER} as '${NAME}'"
exec python3 -u /bridge.py
