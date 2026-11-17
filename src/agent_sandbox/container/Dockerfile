# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
ARG BASE
FROM ${BASE}
# Offline context contains exactly these reviewed files; no RUN or downloads.
COPY protocol.py entrypoint.py launch.py tt_tools.py CONTAINER_ONLY /opt/agent/
USER 65534:65534
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/python", "-I", "/opt/agent/entrypoint.py"]
