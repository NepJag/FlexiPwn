FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Herramientas + sshd para que el atacante pueda entrar por SSH
RUN apt-get update && apt-get install -y \
    sudo \
    vim \
    nano \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Usuario vulnerable + clave conocida (educativo)
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser:ctfpassword" | chpasswd

# VULNERABILIDAD: sudo mal configurado — vim como root sin password
RUN echo "ctfuser ALL=(ALL) NOPASSWD: /usr/bin/vim" >> /etc/sudoers

# sshd: directorio runtime + permitir password auth
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Directorio observado por el monitor de filesystem
RUN mkdir -p /monitored && chmod 755 /monitored

EXPOSE 22

HEALTHCHECK --interval=2s --timeout=2s --start-period=5s --retries=5 \
    CMD pgrep sshd || exit 1

CMD ["/usr/sbin/sshd", "-D"]
