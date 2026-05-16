FROM ubuntu:22.04

# Instalar sudo y herramientas básicas
RUN apt-get update && apt-get install -y \
    sudo \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario vulnerable
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser:ctfpassword" | chpasswd

# VULNERABILIDAD: sudo mal configurado
# Permite ejecutar vim como root sin password
RUN echo "ctfuser ALL=(ALL) NOPASSWD: /usr/bin/vim" >> /etc/sudoers

# Crear directorio compartido para monitoreo
RUN mkdir -p /monitored && chmod 755 /monitored

# Cambiar al usuario vulnerable
USER ctfuser
WORKDIR /home/ctfuser

HEALTHCHECK --interval=2s --timeout=2s --start-period=3s --retries=3 \
      CMD id ctfuser

CMD ["/bin/bash"]