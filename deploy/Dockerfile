FROM python:3.12-slim

# yara-python needs a compiler and libyara's build deps. Built in one layer and
# removed afterwards so the runtime image does not carry a toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libssl-dev libmagic1 \
 && pip install --no-cache-dir yara-python==4.5.1 \
 && apt-get purge -y --auto-remove build-essential libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/netscan
COPY netscan/ ./netscan/
COPY rules/ ./rules/
COPY pyproject.toml ./

# Run as an unprivileged user: this process parses hostile input all day.
RUN useradd --system --no-create-home --uid 10001 netscan \
 && mkdir -p /var/log/netscan /var/lib/netscan/quarantine \
 && chown -R netscan:netscan /var/log/netscan /var/lib/netscan
USER netscan

ENTRYPOINT ["python", "-m", "netscan.cli"]
CMD ["status"]
