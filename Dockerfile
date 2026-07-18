# NOTE: base image tags are intentionally left floating (not pinned by digest).
# Known risk: a re-tagged upstream image could change contents between builds.
# Pin to golang:1.25-bookworm@sha256:<digest> / python:3.11-bookworm@sha256:<digest>
# if reproducible, supply-chain-hardened builds become a requirement.
FROM golang:1.25-bookworm AS go-builder

WORKDIR /src
COPY apps/vulscan-cli ./apps/vulscan-cli
WORKDIR /src/apps/vulscan-cli
RUN go build -o /out/vulscan ./main.go


FROM python:3.11-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VULSCAN_PYTHON=/usr/local/bin/python \
    PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      wget \
      git \
      jq \
      unzip \
      tar \
      xz-utils \
      build-essential \
      pkg-config \
      make \
      gcc \
      g++ \
      nodejs \
      npm \
    && rm -rf /var/lib/apt/lists/*

# Only the Docker CLI is needed (the container talks to the host daemon via
# /var/run/docker.sock). docker.io would drag in the daemon + containerd, so
# install docker-ce-cli from Docker's official apt repo instead.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Keep Go available at runtime for Go parser support and Go target repositories.
COPY --from=go-builder /usr/local/go /usr/local/go

WORKDIR /opt/911VulScan
COPY . /opt/911VulScan

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -e /opt/911VulScan/libs/vulscan-core

COPY --from=go-builder /out/vulscan /usr/local/bin/vulscan

# Run as a non-root user. When mounting /var/run/docker.sock, the container
# user needs the socket's group — e.g.
#   docker run --group-add $(stat -c %g /var/run/docker.sock) ...
# or ensure the host docker GID matches the container's docker group.
RUN groupadd -f docker \
    && useradd -m -s /bin/bash vulscan \
    && usermod -aG docker vulscan \
    && mkdir -p /workspace \
    && chown -R vulscan:vulscan /workspace

USER vulscan
WORKDIR /workspace
CMD ["vulscan", "--help"]
