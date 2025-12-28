#!/bin/bash

# --- CONFIGURACIÓN ---
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NETWORK="agriculture-iot_sensor-net"

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}     AUDITORÍA DE SEGURIDAD AUTOMATIZADA (NMAP)     ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. VERIFICACIÓN DE RED
echo -e "\n${YELLOW}[1/4] Verificando acceso a la red de sensores...${NC}"
if ! docker network ls | grep -q "$NETWORK"; then
    echo -e "${RED}Error: La red $NETWORK no existe. Ejecuta primero setup.sh${NC}"
    exit 1
fi
echo -e "✅ Red detectada: $NETWORK"

# 2. ESCANEO DE PUERTOS EN EL BROKER (EL CORAZÓN)
echo -e "\n${GREEN}[2/4] Escaneando servicios en el Broker MQTT (10.10.1.10)...${NC}"
docker run --rm instrumentisto/nmap -sV -p 1883,9001 10.10.1.10 --network $NETWORK

# 3. PRUEBA DE SEGMENTACIÓN (CONECTIVIDAD IT/OT)
echo -e "\n${GREEN}[3/4] Validando aislamiento entre Sensores y API...${NC}"
# Intentamos conectar del sensor (OT) a la API (IT) usando Python
RESULT=$(docker exec soil-sensor-001 python3 -c "import socket; s = socket.socket(); s.settimeout(2); print('ABIERTA' if s.connect_ex(('172.30.0.20', 8002)) == 0 else 'AISLADA')" 2>/dev/null)

if [ "$RESULT" == "AISLADA" ]; then
    echo -e "✅ SEGURIDAD CORRECTA: El sensor NO puede ver la red de gestión."
else
    echo -e "${RED}❌ ALERTA: La red no está bien aislada. El sensor llegó a la API.${NC}"
fi

# 4. DETECCIÓN DE VULNERABILIDAD (BUFFER OVERFLOW)
echo -e "\n${GREEN}[4/4] Comprobando desbordamiento de buffer en sensores...${NC}"
OVERFLOW=$(docker logs soil-sensor-001 2>&1 | grep -c "VULNERABILITY")

if [ $OVERFLOW -gt 0 ]; then
    echo -e "${RED}⚠️  VULNERABILIDAD DETECTADA: El sensor está procesando datos corruptos.${NC}"
    echo -e "Último registro: $(docker logs soil-sensor-001 2>&1 | grep "VULNERABILITY" | tail -n 1)"
else
    echo -e "✅ No se detectaron desbordamientos en los logs actuales."
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${BLUE}             FIN DEL REPORTE DE AUDITORÍA            ${NC}"
echo -e "${BLUE}====================================================${NC}"