FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    mysql-server \
    python3 \
    python3-pip \
    && pip3 install flask pymysql \
    && rm -rf /var/lib/apt/lists/*

# Habilitar general query log de MySQL apuntado a /var/log/mysql/general.log
RUN echo "\n[mysqld]\ngeneral_log = 1\ngeneral_log_file = /var/log/mysql/general.log\nbind-address = 0.0.0.0\ntls_version=" \
    >> /etc/mysql/mysql.conf.d/mysqld.cnf

# El directorio /var/log/mysql ya existe en la imagen base de mysql-server,
# pero aseguramos permisos para que el bind mount del host sea escribible.
RUN mkdir -p /var/log/mysql && chown mysql:adm /var/log/mysql && chmod 775 /var/log/mysql
RUN mkdir -p /var/log/app && chmod 777 /var/log/app

COPY init.sql /init.sql
COPY app.py /app.py
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 5001

HEALTHCHECK --interval=3s --timeout=3s --start-period=20s --retries=10 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

CMD ["/start.sh"]
