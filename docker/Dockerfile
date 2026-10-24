# Sandbox image for the Hermes terminal backend.
# Python plus project dependencies, run as a non-root user that matches the host user.
FROM python:3.11-slim
ARG USERNAME=blackwater
ARG UID=1000
ARG GID=1000
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt \
 && groupadd -g ${GID} ${USERNAME} \
 && useradd -m -u ${UID} -g ${GID} -s /bin/bash ${USERNAME}
USER ${USERNAME}
WORKDIR /home/${USERNAME}
