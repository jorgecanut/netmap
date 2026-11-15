FROM python:3.12-slim

# openssh-client: the Network tab reads the router over SSH (and creates its key).
# psutil (optional): adds the up/down rate tiles on the This machine tab.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir psutil==7.0.0

WORKDIR /app
COPY netmap.py ./
COPY netmap_core ./netmap_core

# Database, caches and the router key live on a volume.
ENV NETMAP_DATA_DIR=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME /data

EXPOSE 8339

ENTRYPOINT ["python", "netmap.py", "--no-browser"]
