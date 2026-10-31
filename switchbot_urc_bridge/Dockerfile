# Supervisor passes BUILD_FROM from build.yaml; the default is a safe fallback (aarch64 / Pi 64-bit)
# so the image still builds if build.yaml is missing or not picked up.
ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest
FROM ${BUILD_FROM}

# BlueZ client libs + python BLE-peripheral + MQTT.
RUN apk add --no-cache \
      bluez \
      bluez-btmon \
      bluez-libs \
      dbus \
      python3 \
      py3-pip \
      py3-dbus \
      py3-gobject3 \
    && pip3 install --no-cache-dir --break-system-packages \
      bluezero==0.9.0 \
      paho-mqtt==2.1.0 \
      "bleak>=1.0,<2" \
      cryptography

COPY run.sh /run.sh
COPY bridge.py /bridge.py
COPY hci_multi.py /hci_multi.py
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
