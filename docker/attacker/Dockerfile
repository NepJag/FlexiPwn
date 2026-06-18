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
# Visor de estado/objetivos/pistas para el estudiante. El daemon (Capa 4)
# escribe el estado renderizado en /opt/flexipwn/status.txt vía exec_run; el
# script 'flexipwn' (world-readable) solo lo muestra.
RUN mkdir -p /opt/flexipwn && \
    printf '%s\n' "FlexiPwn: el laboratorio esta iniciando. Vuelve a correr flexipwn en unos segundos." > /opt/flexipwn/status.txt && \
    chmod 755 /opt/flexipwn && chmod 644 /opt/flexipwn/status.txt
COPY flexipwn-status.sh /usr/local/bin/flexipwn
RUN chmod 755 /usr/local/bin/flexipwn
EXPOSE 22
HEALTHCHECK --interval=2s --timeout=2s --start-period=10s --retries=5 \
    CMD pgrep sshd || exit 1
CMD ["/usr/sbin/sshd", "-D"]
