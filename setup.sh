#!/bin/bash

# =====================================================
# SETUP AUTOMÁTICO CON GENERACIÓN DE SECRET_KEY
# =====================================================
# Este script hace TODO automáticamente:
# - Genera SECRET_KEY si no existe
# - Configura .env
# - Levanta Docker
# - Inicializa la base de datos
# =====================================================

set -e  # Detener si hay error

# Colores
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'

PROJECT_DIR="agriculture-iot"

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   🚀 SETUP AUTOMÁTICO - AGRO IOT API             ${NC}"
echo -e "${BLUE}====================================================${NC}"

# =====================================================
# 1. VERIFICAR/CREAR .env CON SECRET_KEY AUTOMÁTICA
# =====================================================
echo -e "\n${YELLOW}[1/7] Configurando variables de entorno...${NC}"

if [ ! -f ".env" ]; then
    echo -e "${BLUE}📝 Creando .env con SECRET_KEY segura...${NC}"
    
    # Generar SECRET_KEY automáticamente
    SECRET_KEY=$(openssl rand -hex 32)
    
    cat > .env << EOF
# ==========================================
# CONFIGURACIÓN AUTOMÁTICA - Generado: $(date)
# ==========================================

# ===== JWT Y SEGURIDAD =====
SECRET_KEY=$SECRET_KEY

# ===== BASE DE DATOS =====
DATABASE_URL=sqlite:///./database/data.db

# ===== API =====
API_PORT=8002
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ===== CORS =====
ALLOWED_ORIGINS=http://localhost,http://localhost:80,https://localhost

# ===== MQTT =====
MQTT_BROKER=mosquitto
MQTT_PORT=1883

# ===== CREDENCIALES ADMIN =====
API_USERNAME=superjefe
API_PASSWORD=P@ssw0rd!
EOF
    
    echo -e "${GREEN}✅ .env creado con SECRET_KEY: ${SECRET_KEY:0:16}...${NC}"
    
else
    echo -e "${BLUE}📄 .env encontrado, verificando SECRET_KEY...${NC}"
    
    # Verificar si SECRET_KEY es válida
    CURRENT_KEY=$(grep "^SECRET_KEY=" .env | cut -d'=' -f2)
    
    if [ -z "$CURRENT_KEY" ] || [ "$CURRENT_KEY" = "CAMBIAR_ESTO_POR_UNA_CLAVE_SEGURA_DE_64_CARACTERES_MINIMO" ]; then
        echo -e "${YELLOW}⚠️  SECRET_KEY no válida, regenerando...${NC}"
        
        # Generar nueva SECRET_KEY
        NEW_SECRET_KEY=$(openssl rand -hex 32)
        
        # Reemplazar en .env
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s|^SECRET_KEY=.*|SECRET_KEY=$NEW_SECRET_KEY|" .env
        else
            sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$NEW_SECRET_KEY|" .env
        fi
        
        echo -e "${GREEN}✅ SECRET_KEY regenerada: ${NEW_SECRET_KEY:0:16}...${NC}"
    else
        echo -e "${GREEN}✅ SECRET_KEY válida encontrada${NC}"
    fi
fi

# Cargar variables de entorno
set -a
source .env
set +a

echo -e "${GREEN}✅ Variables cargadas:${NC}"
echo -e "   - SECRET_KEY: ${SECRET_KEY:0:16}..."
echo -e "   - API_PORT: $API_PORT"
echo -e "   - API_USERNAME: $API_USERNAME"

# =====================================================
# 2. COPIAR .env A agriculture-iot
# =====================================================
echo -e "\n${YELLOW}[2/7] Sincronizando configuración con Docker...${NC}"

cp .env "$PROJECT_DIR/.env"
echo -e "${GREEN}✅ .env copiado a $PROJECT_DIR/${NC}"

# =====================================================
# 3. VERIFICAR/INSTALAR DEPENDENCIAS
# =====================================================
echo -e "\n${YELLOW}[3/7] Verificando dependencias del sistema...${NC}"

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker no encontrado, instalando...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl start docker
    systemctl enable docker
fi

# Verificar Docker Compose
if ! command -v docker compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose no encontrado${NC}"
    echo -e "${YELLOW}Instala Docker Compose y vuelve a ejecutar${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker y Docker Compose disponibles${NC}"

# =====================================================
# 4. VERIFICAR PUERTOS LIBRES
# =====================================================
echo -e "\n${YELLOW}[4/7] Verificando puertos...${NC}"

for port in 80 8002 1883 9001; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Puerto $port en uso, liberando...${NC}"
        lsof -ti:$port | xargs kill -9 2>/dev/null || true
    fi
done

echo -e "${GREEN}✅ Puertos libres${NC}"

# =====================================================
# 5. DETENER CONTENEDORES PREVIOS
# =====================================================
echo -e "\n${YELLOW}[5/7] Limpiando contenedores previos...${NC}"

cd "$PROJECT_DIR"
docker compose down -v --remove-orphans 2>/dev/null || true
cd ..

echo -e "${GREEN}✅ Contenedores limpiados${NC}"

# =====================================================
# 6. CONSTRUIR Y LEVANTAR SERVICIOS
# =====================================================
echo -e "\n${YELLOW}[6/7] Construyendo y levantando servicios...${NC}"

cd "$PROJECT_DIR"

# Exportar SECRET_KEY al entorno de Docker
export SECRET_KEY

# Levantar servicios
docker compose up -d --build

cd ..

echo -e "${GREEN}✅ Servicios levantados${NC}"

# =====================================================
# 7. INICIALIZAR BASE DE DATOS
# =====================================================
echo -e "\n${YELLOW}[7/7] Inicializando base de datos...${NC}"

# Esperar a que la API esté lista
echo -e "${BLUE}Esperando a que la API esté lista...${NC}"
for i in {1..30}; do
    if docker exec asset-api curl -s http://localhost:8002/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ API lista después de $i segundos${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Timeout esperando a la API${NC}"
        echo -e "${YELLOW}Logs de la API:${NC}"
        docker logs asset-api --tail 30
        exit 1
    fi
    sleep 1
done

# Crear usuario admin
echo -e "${BLUE}Creando usuario administrador...${NC}"

docker exec -i asset-api python << 'PYTHON_EOF'
import sys
sys.path.append('.')

try:
    from sqlmodel import Session, select, SQLModel
    from datetime import datetime, timezone
    from app.core.database import engine
    from app.models.asset import User
    from app.core.security import get_password_hash

    # Crear tablas
    SQLModel.metadata.create_all(engine)
    print("✅ Tablas creadas")

    # Crear usuario admin
    with Session(engine) as session:
        admin = session.exec(
            select(User).where(User.username == 'superjefe')
        ).first()
        
        if not admin:
            admin = User(
                username='superjefe',
                email='admin@agroiot.com',
                hashed_password=get_password_hash('P@ssw0rd!'),
                is_active=True,
                role='admin',
                created_at=datetime.now(timezone.utc)
            )
            session.add(admin)
            session.commit()
            print("✅ Usuario admin creado: superjefe / P@ssw0rd!")
        else:
            print("✅ Usuario admin ya existe")

except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
PYTHON_EOF

echo -e "${GREEN}✅ Base de datos inicializada${NC}"

# =====================================================
# VERIFICACIÓN FINAL
# =====================================================
echo -e "\n${YELLOW}Verificando servicios...${NC}"

# Verificar API
if curl -s http://localhost:8002/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API respondiendo en http://localhost:8002${NC}"
else
    echo -e "${RED}❌ API no responde${NC}"
    docker logs asset-api --tail 20
fi

# Verificar Frontend
if curl -s http://localhost > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Frontend respondiendo en http://localhost${NC}"
else
    echo -e "${YELLOW}⚠️  Frontend no responde (puede tardar unos segundos)${NC}"
fi

# Verificar SECRET_KEY en logs
echo -e "\n${YELLOW}Verificando SECRET_KEY en la API...${NC}"
if docker logs asset-api 2>&1 | grep -q "SECRET_KEY cargada correctamente"; then
    echo -e "${GREEN}✅ SECRET_KEY cargada correctamente en la API${NC}"
else
    echo -e "${RED}❌ Problema con SECRET_KEY${NC}"
    docker logs asset-api --tail 30
fi

# =====================================================
# RESUMEN FINAL
# =====================================================
echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}          🎉 SISTEMA DESPLEGADO CON ÉXITO 🎉       ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e ""
echo -e "${GREEN}📡 Servicios disponibles:${NC}"
echo -e "   🌐 Frontend:     ${YELLOW}http://localhost${NC}"
echo -e "   📊 API Docs:     ${YELLOW}http://localhost:8002/docs${NC}"
echo -e "   ❤️  Health Check: ${YELLOW}http://localhost:8002/health${NC}"
echo -e "   📡 MQTT Broker:  ${YELLOW}mqtt://localhost:1883${NC}"
echo -e ""
echo -e "${GREEN}🔐 Credenciales de acceso:${NC}"
echo -e "   Usuario:  ${YELLOW}superjefe${NC}"
echo -e "   Password: ${YELLOW}P@ssw0rd!${NC}"
echo -e ""
echo -e "${GREEN}🔑 SECRET_KEY:${NC}"
echo -e "   ${YELLOW}${SECRET_KEY:0:32}...${NC}"
echo -e "   ${BLUE}(Guardada en .env)${NC}"
echo -e ""
echo -e "${YELLOW}📝 Comandos útiles:${NC}"
echo -e "   Ver logs API:      ${BLUE}docker logs -f asset-api${NC}"
echo -e "   Ver logs Frontend: ${BLUE}docker logs -f agriculture-dashboard${NC}"
echo -e "   Detener todo:      ${BLUE}cd $PROJECT_DIR && docker compose down${NC}"
echo -e "   Reiniciar:         ${BLUE}sudo ./setup.sh${NC}"
echo -e ""
echo -e "${BLUE}====================================================${NC}"

# Abrir navegador automáticamente
if command -v xdg-open > /dev/null 2>&1; then
    echo -e "${GREEN}Abriendo navegador...${NC}"
    sleep 2
    xdg-open http://localhost 2>/dev/null &
elif command -v open > /dev/null 2>&1; then
    open http://localhost 2>/dev/null &
fi

echo -e "${GREEN}✅ Setup completado${NC}"