FROM python:3.10-slim

WORKDIR /app

# Instalar dependencias
RUN pip install --no-cache-dir \
    paho-mqtt==1.6.1 \
    requests==2.31.0

COPY mqtt_gateway.py .

# Usuario no root
RUN useradd -m gateway
USER gateway

CMD ["python", "mqtt_gateway.py"]