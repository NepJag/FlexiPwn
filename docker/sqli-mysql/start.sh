#!/bin/bash
set -e

# Asegurar que el directorio de logs de app existe con permisos correctos
mkdir -p /var/log/app && chmod 777 /var/log/app

# Pre-crear el general.log con permisos legibles por el host (FlexiPwn bind-mount)
# MySQL usa el archivo existente sin cambiar sus permisos
touch /var/log/mysql/general.log
chown mysql:adm /var/log/mysql/general.log
chmod 644 /var/log/mysql/general.log

# Iniciar MySQL
service mysql start

# Esperar a que MySQL esté listo para aceptar conexiones
for i in $(seq 1 20); do
    if mysqladmin -u root ping --silent 2>/dev/null; then
        break
    fi
    sleep 1
done

# Cargar schema y datos iniciales
mysql -u root < /init.sql

# Iniciar Flask
python3 /app.py
