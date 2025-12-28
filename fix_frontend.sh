#!/bin/bash

# =====================================================
# SCRIPT PARA ARREGLAR ACCESO AL FRONTEND
# =====================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================================${NC}"
echo -e "${BLUE}       🔧 ARREGLANDO ACCESO AL FRONTEND               ${NC}"
echo -e "${BLUE}========================================================${NC}"

# Verificar ubicación
if [ ! -d "agriculture-iot" ]; then
    echo -e "${RED}❌ ERROR: Ejecuta este script desde la raíz del proyecto${NC}"
    exit 1
fi

# =====================================================
# 1. VERIFICAR SI LOS CONTENEDORES ESTÁN CORRIENDO
# =====================================================
echo -e "\n${YELLOW}[1/6] Verificando contenedores...${NC}"

if ! docker ps | grep -q "agriculture-dashboard"; then
    echo -e "${RED}❌ El contenedor del frontend no está corriendo${NC}"
    echo -e "${YELLOW}Reconstruyendo...${NC}"
    cd agriculture-iot
    docker compose up -d --build frontend
    cd ..
    sleep 5
fi

if ! docker ps | grep -q "asset-api"; then
    echo -e "${RED}❌ El contenedor de la API no está corriendo${NC}"
    echo -e "${YELLOW}Reconstruyendo...${NC}"
    cd agriculture-iot
    docker compose up -d --build asset-api
    cd ..
    sleep 5
fi

echo -e "${GREEN}✅ Contenedores verificados${NC}"

# =====================================================
# 2. VERIFICAR CERTIFICADOS SSL
# =====================================================
echo -e "\n${YELLOW}[2/6] Verificando certificados SSL...${NC}"

if [ ! -f "frontend/certs/cert.pem" ] || [ ! -f "frontend/certs/key.pem" ]; then
    echo -e "${YELLOW}Regenerando certificados del frontend...${NC}"
    mkdir -p frontend/certs
    cd frontend/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout key.pem -out cert.pem \
      -subj "/C=ES/ST=Alava/L=Vitoria/O=EUNEIZ/CN=localhost" 2>/dev/null
    cd ../..
fi

echo -e "${GREEN}✅ Certificados SSL verificados${NC}"

# =====================================================
# 3. CREAR NGINX.CONF SIMPLE (SIN SSL PARA EMPEZAR)
# =====================================================
echo -e "\n${YELLOW}[3/6] Configurando NGINX (modo HTTP simple)...${NC}"

cat > frontend/nginx.conf << 'NGINX_EOF'
server {
    listen 80;
    server_name localhost;

    # Servir archivos estáticos
    location / {
        root /usr/share/nginx/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Proxy a la API
    location /api/ {
        rewrite ^/api/(.*)$ /$1 break;
        proxy_pass http://172.30.0.20:8002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX_EOF

echo -e "${GREEN}✅ NGINX configurado en modo HTTP${NC}"

# =====================================================
# 4. REINICIAR FRONTEND
# =====================================================
echo -e "\n${YELLOW}[4/6] Reiniciando frontend...${NC}"

cd agriculture-iot
docker compose restart frontend
cd ..

sleep 5

echo -e "${GREEN}✅ Frontend reiniciado${NC}"

# =====================================================
# 5. VERIFICAR CONECTIVIDAD
# =====================================================
echo -e "\n${YELLOW}[5/6] Verificando conectividad...${NC}"

# Verificar API
if curl -s http://localhost:8002/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API responde en http://localhost:8002${NC}"
else
    echo -e "${RED}❌ API no responde${NC}"
    echo -e "${YELLOW}Logs de la API:${NC}"
    docker logs asset-api --tail 20
fi

# Verificar Frontend
if curl -s http://localhost > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Frontend responde en http://localhost${NC}"
else
    echo -e "${RED}❌ Frontend no responde${NC}"
    echo -e "${YELLOW}Logs del frontend:${NC}"
    docker logs agriculture-dashboard --tail 20
fi

# =====================================================
# 6. VERIFICAR PUERTOS
# =====================================================
echo -e "\n${YELLOW}[6/6] Verificando puertos...${NC}"

echo -e "${BLUE}Puertos abiertos:${NC}"
sudo netstat -tulpn | grep -E ':(80|8002|443)' || echo "No se encontraron puertos abiertos"

# =====================================================
# RESUMEN Y PRÓXIMOS PASOS
# =====================================================
echo -e "\n${BLUE}========================================================${NC}"
echo -e "${GREEN}              ✅ DIAGNÓSTICO COMPLETADO                ${NC}"
echo -e "${BLUE}========================================================${NC}"
echo -e ""
echo -e "${GREEN}URLs de acceso:${NC}"
echo -e "  🌐 Frontend:    ${YELLOW}http://localhost${NC}"
echo -e "  📊 API (Docs):  ${YELLOW}http://localhost:8002/docs${NC}"
echo -e "  ❤️  Health:      ${YELLOW}http://localhost:8002/health${NC}"
echo -e ""
echo -e "${YELLOW}📝 Prueba de conectividad:${NC}"
echo -e "  ${BLUE}curl http://localhost:8002/health${NC}"
echo -e "  ${BLUE}curl http://localhost${NC}"
echo -e ""
echo -e "${YELLOW}🔍 Ver logs en tiempo real:${NC}"
echo -e "  ${BLUE}docker logs -f asset-api${NC}"
echo -e "  ${BLUE}docker logs -f agriculture-dashboard${NC}"
echo -e ""
echo -e "${YELLOW}🔄 Si aún no funciona:${NC}"
echo -e "  ${BLUE}cd agriculture-iot${NC}"
echo -e "  ${BLUE}docker compose down${NC}"
echo -e "  ${BLUE}docker compose up -d --build${NC}"
echo -e ""
echo -e "${BLUE}========================================================${NC}"

# Intentar abrir en el navegador
if command -v xdg-open > /dev/null; then
    echo -e "${GREEN}Abriendo navegador...${NC}"
    xdg-open http://localhost 2>/dev/null &
fi