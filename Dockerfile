FROM python:3.12-slim

# psutil is optional for NetMap, but in a container it adds the down/up rate tiles.
RUN pip install --no-cache-dir psutil==7.0.0

WORKDIR /app
COPY netmap.py ./

# Caches (geolocation, threat lists) go to a volume instead of beside the script.
ENV NETMAP_DATA_DIR=/data \
    PYTHONUNBUFFERED=1
VOLUME /data

EXPOSE 8339

# No browser inside a container; open http://localhost:8339 on the host.
ENTRYPOINT ["python", "netmap.py", "--no-browser"]
