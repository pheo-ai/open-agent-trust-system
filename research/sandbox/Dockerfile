# A stand-in for a developer's machine: the toolchains the corpus's
# install steps actually reach for. Not anyone's real laptop, which is a
# stated confound in the study that uses it.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip \
      python3 python3-pip python3-venv \
      nodejs npm golang-go \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent
USER agent
WORKDIR /home/agent
