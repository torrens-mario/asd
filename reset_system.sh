#!/bin/bash

# Colores para la terminal
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}--- INICIANDO RESET TOTAL DEL SISTEMA ---${NC}"

# 1. Detener y eliminar todo (incluyendo volúmenes de DB)
echo -e "\n1. Eliminando contenedores y volúmenes previos..."
docker compose down -v

# 2. Borrar el archivo de base de datos físicamente si existe
if [ -f "./database/data.db" ]; then
    sudo rm ./database/data.db
    echo "Archivo data.db eliminado."
fi

# 3. Limpiar logs del sistema
echo -e "2. Limpiando archivos de log de Docker..."
sudo truncate -s 0 $(docker inspect --format='{{.LogPath}}' $(docker ps -aq)) 2>/dev/null

# 4. Lanzar el setup original
echo -e "\n3. Ejecutando nuevo despliegue limpio..."
chmod +x setup.sh
./setup.sh

echo -e "\n${GREEN}=== SISTEMA RESETEADO Y LISTO PARA LA DEMO ===${NC}"
echo -e "Acceso: http://localhost"
echo -e "Usuario: superjefe / P@ssw0rd!"