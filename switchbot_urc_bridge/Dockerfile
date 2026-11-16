# Supervisor passes BUILD_FROM from build.yaml; the default is a safe fallback (aarch64 / Pi 64-bit)
# so the image still builds if build.yaml is missing or not picked up.
ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest
FROM ${BUILD_FROM}

# btmon is only used when the optional HCI trace is enabled.
RUN apk add --no-cache bluez-btmon python3 py3-pip \
    && pip3 install --no-cache-dir --break-system-packages \
      paho-mqtt==2.1.0 \
      cryptography

COPY run.sh /run.sh
COPY bridge.py /bridge.py
COPY hci_multi.py /hci_multi.py
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
