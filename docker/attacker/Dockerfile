FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    openssh-server \
    netcat-openbsd \
    curl \
    nmap \
    sudo \
    && rm -rf /var/lib/apt/lists/* \
    && echo "%sudo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
RUN useradd -m -s /bin/bash attacker && \
    echo "attacker:attacker" | chpasswd
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
HEALTHCHECK --interval=2s --timeout=2s --start-period=10s --retries=5 \
    CMD pgrep sshd || exit 1
CMD ["/usr/sbin/sshd", "-D"]
