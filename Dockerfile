# Collector image - runs ONE collection pass and exits. It is a scheduled job,
# not a service, so there is no long-running process here.
#
# Scope: this image only COLLECTS (collector.py writes today's raw dumps under
# Output/). Everything downstream - CDB lists, the staleness guard, VirusTotal
# enrichment, the dashboard, pruning, checksums - runs on the host through
# build_lists.sh, because the guard reads the previous list from git history
# (`git show HEAD:malicious-ips.txt`) and .git is deliberately not in the image.
#
# The previous CMD ran `tweetfeed.py`, a file that has not existed since the
# Twitter-era pipeline was replaced, so `docker compose up` could never work.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Deliberately no apt-get: the collector speaks HTTPS through requests only.
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# Only the collector is copied. See .dockerignore for what must never enter an
# image layer (Output/ is hundreds of MB; .abusech_auth_key is a credential).
COPY collector.py ./

# Non-root: the process writes only into the mounted Output volume.
RUN useradd --create-home --uid 10001 collector \
    && mkdir -p /app/Output \
    && chown -R collector:collector /app
# Keeps a bare `docker run` non-root. docker-compose.yml overrides this with
# the host uid:gid, because Output/ is a bind mount owned by your user and
# uid 10001 cannot create subdirectories in a 755 directory it does not own.
USER collector

CMD ["python", "collector.py"]
