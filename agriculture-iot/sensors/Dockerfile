# Usamos una versión ligera de Python
FROM python:3.9-slim

# Evita que Python genere archivos .pyc y fuerza el log inmediato
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalamos la librería necesaria para MQTT
RUN pip install paho-mqtt

# Copiamos todos los scripts (.py) de la carpeta sensors al contenedor
COPY . .

# Comando por defecto (aunque docker-compose lo sobrescribe, es bueno tenerlo)
CMD ["python", "temperature_sensor.py"]