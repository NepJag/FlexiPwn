# docker/attacker-web/Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/bash"]