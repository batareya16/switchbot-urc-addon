#!/usr/bin/with-contenv bashio
# Read add-on options + MQTT service credentials, then launch the BLE-peripheral bridge.
set -e

# Supervisor can retain the options saved by older releases.
for option in name diagnostic_scan prewarm_remote_cache direct_att raw_att_idle_timeout \
  raw_att_keepalive_interval raw_att_keepalive_window; do
  if bashio::config.exists "${option}"; then
    bashio::addon.option "${option}" || bashio::log.warning "Could not remove obsolete option ${option}"
  fi
done

ADAPTER="$(bashio::config 'adapter')"
ADDRESSES="$(bashio::config 'addresses')"
# bashio renders an unset optional as the string "null"; the bridge wants it empty.
if [ "${ADDRESSES}" = "null" ]; then ADDRESSES=""; fi
REMOTE_ADDRESS="$(bashio::config 'remote_address')"
TOPIC="$(bashio::config 'mqtt_topic')"
DISCOVERY="$(bashio::config 'discovery')"
HCI_TRACE="$(bashio::config 'hci_trace')"
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

export ADAPTER ADDRESSES REMOTE_ADDRESS TOPIC DISCOVERY HCI_TRACE DEVICE_KEY
export CONN_INTERVAL_MIN_MS CONN_INTERVAL_MAX_MS

bashio::log.info "Starting SwitchBot URC Bridge on adapter ${ADAPTER}"
exec python3 -u /bridge.py
