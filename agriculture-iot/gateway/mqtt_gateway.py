"""
MQTT Gateway - Versión Inteligente (Sin duplicados y con tipos correctos)
"""
import paho.mqtt.client as mqtt
import json
import requests
import os
import time
import logging 
from datetime import datetime
from typing import Dict, Any

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración de Variables de Entorno
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
API_URL = os.getenv("API_URL", "http://localhost:8002")
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "admin123")

class MQTTGateway:
    def __init__(self):
        self.client = mqtt.Client(client_id="mqtt_gateway")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.api_token = None
        
        # MEMORIA DEL ROBOT: Diccionario para guardar { "Nombre Sensor": ID_Base_Datos }
        self.asset_memory = {} 

    def authenticate_api(self) -> bool:
        """Autenticar y obtener Token"""
        logger.info(f"🔑 Autenticando en API como {API_USERNAME}...")
        try:
            response = requests.post(
                f"{API_URL}/auth/login",
                data={"username": API_USERNAME, "password": API_PASSWORD}, 
                timeout=10
            )
            if response.status_code == 200:
                self.api_token = response.json()["access_token"]
                logger.info("✅ Token obtenido correctamente.")
                self.load_existing_assets() # <--- AL LOGUEARSE, CARGAMOS LA MEMORIA
                return True
            else:
                logger.error(f"❌ Error Login: {response.text}")
                return False
        except Exception as e:
            logger.error(f"❌ Error conexión Login: {e}")
            return False

    def load_existing_assets(self):
        """Descarga la lista de activos actuales para no duplicarlos"""
        try:
            headers = {"Authorization": f"Bearer {self.api_token}"}
            response = requests.get(f"{API_URL}/assets/", headers=headers)
            if response.status_code == 200:
                assets = response.json()
                # Guardamos en memoria: { "Sensor IoT: temp_001": 5, ... }
                for asset in assets:
                    self.asset_memory[asset["name"]] = asset["id"]
                logger.info(f"🧠 Memoria cargada: {len(self.asset_memory)} activos reconocidos.")
        except Exception as e:
            logger.error(f"⚠️ No pude cargar la memoria inicial: {e}")

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("✅ Conectado a MQTT. Suscribiendo...")
            client.subscribe("agriculture/sensors/#")
        else:
            logger.error(f"❌ Error MQTT: {rc}")

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            self.process_sensor_data(payload) # Simplificado
        except Exception as e:
            logger.error(f"Error procesando mensaje: {e}")

    def process_sensor_data(self, payload: Dict[str, Any]):
        if not self.api_token:
            if not self.authenticate_api(): return

        # 1. Datos del mensaje MQTT
        sensor_hostname = payload.get("sensor_id") # Usamos el sensor_id como hostname único
        val = payload.get("value")
        
        # Variable para guardar el ID si lo encontramos
        asset_db_id = self.asset_memory.get(sensor_hostname)
        current_asset_data = None

        # 2. Si no está en memoria, BUSCAMOS en la API (Anti-Amnesia)
        if not asset_db_id:
            try:
                # Buscamos por el nombre técnico (hostname/sensor_id)
                # Asumimos que tu API permite filtrar ?search=... o filtramos a mano
                r = requests.get(f"{API_URL}/assets/?search={sensor_hostname}", 
                               headers={"Authorization": f"Bearer {self.api_token}"})
                
                if r.status_code == 200:
                    assets_found = r.json()
                    # Buscamos si alguno coincide exactamente con nuestro sensor
                    for asset in assets_found:
                        if asset.get("hostname") == sensor_hostname or asset.get("name") == f"Sensor IoT: {sensor_hostname}":
                            asset_db_id = asset["id"]
                            self.asset_memory[sensor_hostname] = asset_db_id # ¡Lo recordamos!
                            current_asset_data = asset
                            break
            except Exception as e:
                logger.error(f"Error buscando activo en API: {e}")

        # 3. Si ya tenemos ID (porque estaba en memoria o lo acabamos de encontrar) -> ACTUALIZAR
        if asset_db_id:
            # Si no cargamos los datos antes, los pedimos ahora para asegurar
            if not current_asset_data:
                try:
                    r = requests.get(f"{API_URL}/assets/{asset_db_id}", 
                                   headers={"Authorization": f"Bearer {self.api_token}"})
                    if r.status_code == 200:
                        current_asset_data = r.json()
                except:
                    pass

            if current_asset_data:
                # Mantenemos el nombre y ubicación que TÚ pusiste en la web
                update_data = {
                    "name": current_asset_data["name"],         # <--- NO TOCAR
                    "location": current_asset_data["location"], # <--- NO TOCAR
                    "asset_type": current_asset_data["asset_type"],
                    "status": "active",
                    "risk_level": current_asset_data["risk_level"],
                    # Solo actualizamos la descripción con el valor nuevo
                    "description": f"Lectura en vivo: {val} {payload.get('unit', '')}"
                }
                
                try:
                    requests.put(f"{API_URL}/assets/{asset_db_id}", json=update_data, 
                               headers={"Authorization": f"Bearer {self.api_token}"})
                    logger.info(f"🔄 Actualizado (respetando datos): {current_asset_data['name']}")
                except Exception as e:
                    logger.error(f"Error haciendo PUT: {e}")
            else:
                logger.warning("Tenemos ID pero no pudimos leer el activo. Saltando.")

        # 4. Si NO existe de ninguna forma -> CREAR NUEVO USANDO DATOS DEL SENSOR
        else:
            # Aquí está la magia: Usamos payload.get() para leer lo que envía el sensor
            new_asset_data = {
                # Si el sensor envía nombre, úsalo. Si no, usa el ID técnico.
                "name": payload.get("name", f"Sensor IoT: {sensor_hostname}"),
                
                "asset_type": "sensor",
                "hostname": sensor_hostname,
                
                # Leemos la ubicación, IP y Riesgo aleatorios del paquete JSON
                "location": payload.get("location", "Ubicación Desconocida"),
                "ip_address": payload.get("ip_address"),
                "risk_level": payload.get("risk_level", "low"),
                "status": payload.get("status", "active"),
                
                "description": f"Lectura inicial: {val} {payload.get('unit', '')}"
            }
            
            try:
                resp = requests.post(f"{API_URL}/assets/", json=new_asset_data, 
                                   headers={"Authorization": f"Bearer {self.api_token}"})
                if resp.status_code in [200, 201]:
                    new_id = resp.json().get("id")
                    self.asset_memory[sensor_hostname] = new_id
                    logger.info(f"✨ Nuevo sensor creado con identidad aleatoria: {new_asset_data['name']}")
            except Exception as e:
                logger.error(f"Error creando activo: {e}")

    def run(self):
        while True:
            try:
                self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
                break
            except:
                time.sleep(5)
        
        self.authenticate_api()
        self.client.loop_forever()

if __name__ == "__main__":
    MQTTGateway().run()