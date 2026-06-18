#!/bin/bash
# Visor de FlexiPwn para el estudiante: muestra objetivos, pistas y progreso
# del ejercicio en curso.
#
# Es deliberadamente "tonto": el daemon de FlexiPwn (Capa 4) renderiza el estado
# y lo escribe en /opt/flexipwn/status.txt vía exec_run; este script solo lo
# muestra. La imagen atacante no conoce nada de FlexiPwn más allá de esto.
status_file=/opt/flexipwn/status.txt
if [ -r "$status_file" ]; then
    cat "$status_file"
else
    echo "FlexiPwn: aun no hay estado disponible. Intenta de nuevo en unos segundos."
fi
