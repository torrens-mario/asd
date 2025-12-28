FROM eclipse-mosquitto:2.0.15

# VULNERABILIDAD CONTROLADA: Mosquitto 2.0.15 tiene CVE-2023-0809 (severity: medium)
# Descripción: Memory leak en procesamiento de mensajes grandes
# Mitigación: Configurar max_packet_size

# Copiar configuración personalizada
COPY mosquitto.conf /mosquitto/config/mosquitto.conf

# Crear directorio de datos
RUN mkdir -p /mosquitto/data /mosquitto/log

# Permisos
RUN chown -R mosquitto:mosquitto /mosquitto

EXPOSE 1883 9001

CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]