"""
Simulador de Sensor de Temperatura DHT22
Simula datos de temperatura y humedad para invernadero
"""
import json
import time
import random
from datetime import datetime
import os
import logging
import paho.mqtt.client as mqtt

# VULNERABILIDAD CONTROLADA: Logging de credenciales (CWE-532)
# Se loguean datos sensibles para demostración
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SENSOR_ID = os.getenv("SENSOR_ID", "temp_dht22_001")
ASSET_ID = int(os.getenv("ASSET_ID", "10"))
LOCATION = os.getenv("LOCATION", "Unknown")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", "10"))  # segundos

class TemperatureSensor:
    """Simulador de sensor DHT22"""
    
    def __init__(self):
        self.client = mqtt.Client(client_id=SENSOR_ID)

        # === GENERADOR DE IDENTIDAD ALEATORIA ===
        possible_locations = ["Invernadero A", "Invernadero B", "Laboratorio", "Campo Norte", "Bodega", "Secadero", "Silo 4"]
        possible_risks = ["low", "medium", "high", "critical"]
        possible_statuses = ["active", "maintenance", "active", "active"] # Más probabilidad de active
        
        # 1. Nombre aleatorio
        self.random_name = f"Sensor {random.choice(['Alpha', 'Beta', 'Gamma', 'Delta'])} {random.randint(100, 999)}"
        
        # 2. Ubicación aleatoria
        self.random_location = random.choice(possible_locations)
        
        # 3. IP Falsa aleatoria
        self.random_ip = f"192.168.1.{random.randint(10, 250)}"
        
        # 4. Riesgo y Estado inicial
        self.random_risk = random.choice(possible_risks)
        self.random_status = random.choice(possible_statuses)

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        
        # Valores base (simulación realista para Sevilla en noviembre)
        self.base_temp = 18.0  # °C
        self.base_humidity = 65.0  # %
        
        # Variación diurna
        self.temp_amplitude = 5.0  # ±5°C
        self.humidity_amplitude = 15.0  # ±15%
        
        # Estado del sensor
        self.battery_level = 100
        self.firmware_version = "1.2.3"
        
        # VULNERABILIDAD CONTROLADA: Credenciales hardcodeadas (CWE-798)
        # En un escenario real, esto permitiría acceso no autorizado
        self.admin_user = "admin"
        self.admin_pass = "admin123"  # Contraseña débil
        
        logger.warning(f" SECURITY: Hardcoded credentials detected: {self.admin_user}:{self.admin_pass}")
    
    def on_connect(self, client, userdata, flags, rc):
        """Callback cuando se conecta al broker"""
        if rc == 0:
            logger.info(f" Connected to MQTT Broker: {MQTT_BROKER}:{MQTT_PORT}")
        else:
            logger.error(f" Connection failed with code {rc}")
    
    def on_disconnect(self, client, userdata, rc):
        """Callback cuando se desconecta"""
        logger.warning(f" Disconnected from broker (code: {rc})")
    
    def generate_temperature(self) -> float:
        """Generar temperatura realista con variación diurna"""
        # Hora del día (0-24)
        hour = datetime.now().hour
        
        # Variación diurna (sinusoidal)
        # Pico a las 14:00, mínimo a las 6:00
        time_factor = (hour - 6) / 24.0 * 2 * 3.14159
        diurnal_variation = self.temp_amplitude * (0.5 + 0.5 * (1 + (time_factor)))
        
        # Ruido aleatorio
        noise = random.gauss(0, 0.5)
        
        temp = self.base_temp + diurnal_variation + noise
        
        # Clamp entre rangos realistas
        return round(max(10.0, min(35.0, temp)), 2)
    
    def generate_humidity(self) -> float:
        """Generar humedad relativa (inversa a temperatura)"""
        temp = self.generate_temperature()
        
        # Humedad inversamente proporcional a temperatura
        humidity = self.base_humidity - (temp - self.base_temp) * 2
        
        # Ruido
        noise = random.gauss(0, 2)
        humidity += noise
        
        # Clamp entre 30-95%
        return round(max(30.0, min(95.0, humidity)), 2)
    
    def generate_payload(self) -> dict:
        """Generar payload JSON PLANO para el Gateway"""
        
        # Simular descarga de batería
        self.battery_level = max(0, self.battery_level - random.uniform(0, 0.01))
        
        # Obtenemos temperatura y humedad
        temp = self.generate_temperature()
        hum = self.generate_humidity()
        
        # CONSTRUIMOS EL JSON PLANO QUE ESPERA EL GATEWAY
        payload = {
            "sensor_id": SENSOR_ID, # El ID técnico (mqtt) se mantiene
            "asset_id": ASSET_ID,
            "timestamp": time.time(),
            
            "value": temp,
            "unit": "°C",
            
            # --- DATOS ALEATORIOS ---
            "name": self.random_name,         # Enviamos el nombre inventado
            "location": self.random_location, # La ubicación inventada
            "ip_address": self.random_ip,     # La IP inventada
            "risk_level": self.random_risk,   # El riesgo inventado
            "status": self.random_status,     # El estado inventado
            "asset_type": "sensor"            # Esto fijo
        }
        return payload
    
    def run(self):
        """Ejecutar bucle principal del sensor"""
        try:
            # Conectar al broker
            logger.info(f"Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            
            # Iniciar loop en background
            self.client.loop_start()
            
            logger.info(f"Temperature Sensor {SENSOR_ID} started")
            logger.info(f"Publishing to: agriculture/sensors/temperature/{SENSOR_ID}")
            
            while True:
                # Generar y publicar datos
                payload = self.generate_payload()
                topic = f"agriculture/sensors/temperature/{SENSOR_ID}"
                
                result = self.client.publish(
                    topic,
                    json.dumps(payload),
                    qos=1  # At least once delivery
                )
                
                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    # Accedemos directamente a 'value' y 'location'
                    logger.info(f"Published: Temp={payload['value']}°C, Location={payload['location']}")
                else:
                    logger.error(f"Publish failed with code {result.rc}")
                
                # Esperar intervalo
                time.sleep(PUBLISH_INTERVAL)
                
        except KeyboardInterrupt:
            logger.info("Sensor stopped by user")
        except Exception as e:
            logger.error(f"Error: {e}", exc_info=True)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

if __name__ == "__main__":
    sensor = TemperatureSensor()
    sensor.run()