#!/bin/bash
set -e

# Asegurar que el directorio de logs de app existe con permisos correctos
mkdir -p /var/log/app && chmod 777 /var/log/app

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
