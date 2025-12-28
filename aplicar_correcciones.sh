#!/bin/bash

# =====================================================
# SCRIPT AUTOMÁTICO DE CORRECCIONES DE SEGURIDAD
# =====================================================
# Este script corrige las 5 vulnerabilidades críticas
# y deja el proyecto listo para aprobar
# =====================================================

set -e  # Detener si hay algún error

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

echo -e "${BLUE}========================================================${NC}"
echo -e "${BLUE}  🔒 APLICANDO CORRECCIONES DE SEGURIDAD AUTOMÁTICAS  ${NC}"
echo -e "${BLUE}========================================================${NC}"

# Verificar que estamos en la raíz del proyecto
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}❌ ERROR: No estás en la raíz del proyecto${NC}"
    echo -e "${YELLOW}Ejecuta este script desde: Trabajo_API-main/${NC}"
    exit 1
fi

echo -e "\n${GREEN}✅ Directorio correcto detectado${NC}"

# =====================================================
# CORRECCIÓN 1: CREAR .gitignore
# =====================================================
echo -e "\n${YELLOW}[1/10] Creando .gitignore...${NC}"

cat > .gitignore << 'GITIGNORE_EOF'
# ===== PYTHON =====
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# ===== ENTORNOS VIRTUALES =====
venv/
env/
ENV/
.venv

# ===== SECRETOS Y CONFIGURACIÓN =====
.env
.env.local
.env.*.local
*.pem
*.key
*.crt
!requirements.txt

# ===== LOGS =====
logs/
*.log

# ===== BASE DE DATOS =====
*.db
*.sqlite
*.sqlite3
database/data.db

# ===== DOCKER =====
docker-compose.override.yml

# ===== IDE =====
.vscode/
.idea/
*.swp
*.swo
*~

# ===== SISTEMA OPERATIVO =====
.DS_Store
Thumbs.db

# ===== REPORTES DE SEGURIDAD =====
reports/
bandit_report.txt
semgrep_report.json

# ===== CERTIFICADOS =====
frontend/certs/*.pem
agriculture-iot/nginx_certs/*.pem
agriculture-iot/nginx_certs/*.key
agriculture-iot/nginx_certs/*.crt
GITIGNORE_EOF

echo -e "${GREEN}✅ .gitignore creado${NC}"

# =====================================================
# CORRECCIÓN 2: CREAR .env.example
# =====================================================
echo -e "\n${YELLOW}[2/10] Creando .env.example...${NC}"

cat > .env.example << 'ENV_EXAMPLE_EOF'
# ==========================================
# CONFIGURACIÓN DE SEGURIDAD - PROYECTO API
# ==========================================
# IMPORTANTE: Copiar este archivo como .env y cambiar todos los valores

# ===== JWT Y SEGURIDAD =====
# Generar con: openssl rand -hex 32
SECRET_KEY=CAMBIAR_ESTO_POR_UNA_CLAVE_SEGURA_DE_64_CARACTERES_MINIMO

# ===== BASE DE DATOS =====
DATABASE_URL=sqlite:///./database/data.db

# ===== POSTGRES (si usas PostgreSQL) =====
POSTGRES_USER=secure_api_user
POSTGRES_PASSWORD=CAMBIAR_CONTRASEÑA_SEGURA
POSTGRES_DB=secure_api_db

# ===== API =====
API_PORT=8002
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ===== CORS =====
ALLOWED_ORIGINS=http://localhost,http://localhost:80,https://localhost

# ===== MQTT (IoT) =====
MQTT_BROKER=mosquitto
MQTT_PORT=1883

# ===== CREDENCIALES GATEWAY =====
API_USERNAME=superjefe
API_PASSWORD=P@ssw0rd!
ENV_EXAMPLE_EOF

echo -e "${GREEN}✅ .env.example creado${NC}"

# =====================================================
# CORRECCIÓN 3: CORREGIR app/core/security.py
# =====================================================
echo -e "\n${YELLOW}[3/10] Corrigiendo app/core/security.py...${NC}"

cat > app/core/security.py << 'SECURITY_EOF'
from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import os
import sys
import logging

logger = logging.getLogger(__name__)

# ================= CONFIGURACIÓN SEGURA =================
# 🔒 CORRECCIÓN CRÍTICA: SECRET_KEY debe venir SOLO de variables de entorno
SECRET_KEY = os.getenv("SECRET_KEY")

# Validación obligatoria
if not SECRET_KEY:
    logger.critical("❌ FALLO DE SEGURIDAD: SECRET_KEY no está configurada")
    logger.critical("Por favor, configura SECRET_KEY en el archivo .env")
    logger.critical("Genera una con: openssl rand -hex 32")
    sys.exit(1)

if len(SECRET_KEY) < 64:
    logger.critical(f"❌ FALLO: SECRET_KEY demasiado corta ({len(SECRET_KEY)} chars, mín 64)")
    sys.exit(1)

logger.info("✅ SECRET_KEY cargada correctamente")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class TokenData(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = "user"
    token_type: Optional[str] = "access"

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        ph.verify(hashed_password, plain_password)
        if ph.check_needs_rehash(hashed_password):
            logger.info("Password hash necesita rehash")
        return True
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        logger.warning("Hash bcrypt detectado")
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        if pwd_context.verify(plain_password, hashed_password):
            logger.info("Verificación legacy bcrypt OK")
            return True
        return False

def get_password_hash(password: str) -> str:
    return ph.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Access token creado para: {data.get('sub')}")
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Refresh token creado para: {data.get('sub')}")
    return encoded_jwt

def decode_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError: 
        logger.warning("Token expirado")
        raise HTTPException(status_code=401, detail="Token expirado")
    except PyJWTError as e:
        logger.error(f"Error JWT: {e}")
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token inválido")
    username: str = payload.get("sub")
    role: str = payload.get("role", "user")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Payload inválido")
    return {"username": username, "role": role}

def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user["role"] != "admin":
        logger.warning(f"Usuario {user['username']} intentó acción de admin")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requiere privilegios de admin")
    return user

def require_role(role: str):
    def checker(user = Depends(get_current_user)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="Privilegios insuficientes")
        return user
    return checker
SECURITY_EOF

echo -e "${GREEN}✅ app/core/security.py corregido${NC}"

# =====================================================
# CORRECCIÓN 4: CORREGIR app/main.py
# =====================================================
echo -e "\n${YELLOW}[4/10] Corrigiendo app/main.py...${NC}"

cat > app/main.py << 'MAIN_EOF'
from app.routers.assets import assets
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import os
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.messages import messages
from fastapi.middleware.cors import CORSMiddleware
from app.routers.vulnerabilities import vulnerabilities

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agriculture IoT API",
    openapi_url="/openapi.json",
    docs_url="/docs",
    servers=[
        {"url": "/api", "description": "Nginx Proxy"}, 
        {"url": "/", "description": "Directo"}
    ] 
)

# 🔒 CORS RESTRICTIVO
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost,http://localhost:80,https://localhost").split(",")
logger.info(f"🔒 CORS configurado: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    expose_headers=["X-Total-Count"],
    max_age=3600
)

@app.on_event("startup")
def on_startup():
    logger.info("Iniciando API...")
    create_db_and_tables()
    logger.info("API lista")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exec: Exception):
    logger.error(f"Error en {request.method} {request.url.path}: {exec}", exc_info=True, extra={
        "client_host": request.client.host if request.client else "unknown",
        "method": request.method, "path": request.url.path
    })
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Error interno"})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validación fallida en {request.method} {request.url.path}: {exc.errors()}")
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": "Datos inválidos"})

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(f"HTTP {exc.status_code} en {request.url.path}: {exc.detail}")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.get("/health")
def health():
    return {"status": "ok", "cors_origins": ALLOWED_ORIGINS}

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
MAIN_EOF

echo -e "${GREEN}✅ app/main.py corregido${NC}"

# =====================================================
# CORRECCIÓN 5: CORREGIR Dockerfile
# =====================================================
echo -e "\n${YELLOW}[5/10] Corrigiendo Dockerfile...${NC}"

cat > Dockerfile << 'DOCKERFILE_EOF'
# syntax=docker/dockerfile:1
FROM python:3.12-slim

RUN useradd -m appuser
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY .env.example ./.env.example

RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

ENV PORT=8002
EXPOSE 8002

USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
DOCKERFILE_EOF

echo -e "${GREEN}✅ Dockerfile corregido${NC}"

# =====================================================
# CORRECCIÓN 6: CORREGIR docker-compose.yml
# =====================================================
echo -e "\n${YELLOW}[6/10] Corrigiendo agriculture-iot/docker-compose.yml...${NC}"

cat > agriculture-iot/docker-compose.yml << 'COMPOSE_EOF'
services:
  mosquitto:
    build: ./mosquitto
    container_name: mqtt-broker
    hostname: mosquitto
    networks:
      sensor-net:
        ipv4_address: 10.10.1.10
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - mosquitto-data:/mosquitto/data
      - mosquitto-log:/mosquitto/log
    restart: unless-stopped

  asset-api:
    build: ../
    container_name: asset-api
    user: "root"
    hostname: asset-api
    networks:
      mgmt-net:
        ipv4_address: 172.30.0.20
    ports:
      - "8002:8002"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=sqlite:///./database/data.db
      - ALLOWED_ORIGINS=http://localhost,http://localhost:80,https://localhost
      - ACCESS_TOKEN_EXPIRE_MINUTES=15
      - REFRESH_TOKEN_EXPIRE_DAYS=7
    volumes:
      - api-data:/app/database
      - api-logs:/app/logs
    command: uvicorn app.main:app --host 0.0.0.0 --port 8002
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8002/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mqtt-gateway:
    build: ./gateway
    container_name: mqtt-gateway
    hostname: mqtt-gateway
    networks:
      sensor-net:
        ipv4_address: 10.10.1.30
      mgmt-net:
        ipv4_address: 172.30.0.30
    environment:
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - API_URL=http://asset-api:8002
      - API_USERNAME=${API_USERNAME:-superjefe}
      - API_PASSWORD=${API_PASSWORD:-P@ssw0rd!}
    depends_on:
      - mosquitto
      - asset-api
    restart: unless-stopped

  temp-sensor-001:
    build: ./sensors
    container_name: temp-sensor-001
    hostname: temp-dht22-001
    networks:
      sensor-net:
        ipv4_address: 10.10.1.101
    environment:
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - SENSOR_ID=temp_dht22_001
      - ASSET_ID=10
      - LOCATION=Invernadero Tomates
      - PUBLISH_INTERVAL=10
    command: python temperature_sensor.py
    depends_on:
      - mosquitto
    restart: unless-stopped

  temp-sensor-002:
    build: ./sensors
    container_name: temp-sensor-002
    hostname: temp-dht22-002
    networks:
      sensor-net:
        ipv4_address: 10.10.1.102
    environment:
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - SENSOR_ID=temp_dht22_002
      - ASSET_ID=11
      - LOCATION=Bodega de Vinos
      - PUBLISH_INTERVAL=15
    command: python temperature_sensor.py
    depends_on:
      - mosquitto
    restart: unless-stopped

  soil-sensor-001:
    build: ./sensors
    container_name: soil-sensor-001
    hostname: soil-cap-001
    networks:
      sensor-net:
        ipv4_address: 10.10.1.103
    environment:
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - SENSOR_ID=soil_cap_001
      - ASSET_ID=12
      - LOCATION=Campo de Maíz
      - PUBLISH_INTERVAL=30
    command: python soil_moisture_sensor.py
    depends_on:
      - mosquitto
    restart: unless-stopped

  soil-sensor-002:
    build: ./sensors
    container_name: soil-sensor-002
    hostname: soil-cap-002
    networks:
      sensor-net:
        ipv4_address: 10.10.1.104
    environment:
      - MQTT_BROKER=mosquitto
      - MQTT_PORT=1883
      - SENSOR_ID=soil_cap_002
      - ASSET_ID=13
      - LOCATION=Huerto Urbano
      - PUBLISH_INTERVAL=30
    command: python soil_moisture_sensor.py
    depends_on:
      - mosquitto
    restart: unless-stopped

  frontend:
    build: ../frontend
    container_name: agriculture-dashboard
    hostname: frontend
    networks:
      mgmt-net:
        ipv4_address: 172.30.0.40
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ../frontend/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ../frontend:/usr/share/nginx/html:ro
    environment:
      - REACT_APP_API_URL=https://localhost/api
      - REACT_APP_MQTT_WS_URL=ws://localhost:9001
    depends_on:
      - asset-api
    restart: unless-stopped

networks:
  sensor-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.1.0/24
  mgmt-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/16

volumes:
  mosquitto-data:
  mosquitto-log:
  api-data:
  api-logs:
COMPOSE_EOF

echo -e "${GREEN}✅ docker-compose.yml corregido${NC}"

# =====================================================
# CORRECCIÓN 7: LIMPIAR REPOSITORIO
# =====================================================
echo -e "\n${YELLOW}[7/10] Limpiando repositorio...${NC}"

# Eliminar __pycache__
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Limpiar logs
rm -rf logs/*.log 2>/dev/null || true

# Eliminar del índice de git (si está)
git rm -r --cached logs/ 2>/dev/null || true
git rm -r --cached __pycache__/ 2>/dev/null || true
git rm -r --cached frontend/certs/key.pem 2>/dev/null || true
git rm -r --cached agriculture-iot/nginx_certs/server.key 2>/dev/null || true

echo -e "${GREEN}✅ Repositorio limpio${NC}"

# =====================================================
# CORRECCIÓN 8: GENERAR CERTIFICADOS SSL
# =====================================================
echo -e "\n${YELLOW}[8/10] Generando certificados SSL...${NC}"

# Frontend
mkdir -p frontend/certs
cd frontend/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -subj "/C=ES/ST=Alava/L=Vitoria/O=EUNEIZ/CN=localhost" 2>/dev/null
cd ../..

# Agriculture IoT
mkdir -p agriculture-iot/nginx_certs
cd agriculture-iot/nginx_certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/C=ES/ST=Alava/L=Vitoria/O=EUNEIZ/CN=localhost" 2>/dev/null
cd ../..

echo -e "${GREEN}✅ Certificados SSL generados${NC}"

# =====================================================
# CORRECCIÓN 9: CREAR/ACTUALIZAR .env
# =====================================================
echo -e "\n${YELLOW}[9/10] Configurando .env...${NC}"

if [ ! -f ".env" ]; then
    echo -e "${BLUE}Creando .env desde .env.example...${NC}"
    cp .env.example .env
    
    # Generar SECRET_KEY
    echo -e "${GREEN}🔐 Generando SECRET_KEY segura...${NC}"
    SECRET_KEY=$(openssl rand -hex 32)
    
    # Reemplazar en .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    else
        # Linux
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    fi
    
    echo -e "${GREEN}✅ .env creado con SECRET_KEY segura${NC}"
else
    echo -e "${BLUE}.env ya existe, verificando SECRET_KEY...${NC}"
    
    if grep -q "SECRET_KEY=CAMBIAR" .env; then
        echo -e "${YELLOW}SECRET_KEY no configurada, generando nueva...${NC}"
        SECRET_KEY=$(openssl rand -hex 32)
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        else
            sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        fi
        
        echo -e "${GREEN}✅ SECRET_KEY actualizada${NC}"
    else
        echo -e "${GREEN}✅ SECRET_KEY válida encontrada${NC}"
    fi
fi

# =====================================================
# CORRECCIÓN 10: DAR PERMISOS
# =====================================================
echo -e "\n${YELLOW}[10/10] Configurando permisos...${NC}"

chmod +x setup.sh 2>/dev/null || true
chmod +x reset_system.sh 2>/dev/null || true
chmod +x audit_security.sh 2>/dev/null || true

echo -e "${GREEN}✅ Permisos configurados${NC}"

# =====================================================
# RESUMEN FINAL
# =====================================================
echo -e "\n${BLUE}========================================================${NC}"
echo -e "${GREEN}       ✅ CORRECCIONES APLICADAS EXITOSAMENTE ✅        ${NC}"
echo -e "${BLUE}========================================================${NC}"
echo -e ""
echo -e "${GREEN}Archivos corregidos:${NC}"
echo -e "  ✅ .gitignore"
echo -e "  ✅ .env.example"
echo -e "  ✅ .env (con SECRET_KEY segura)"
echo -e "  ✅ app/core/security.py"
echo -e "  ✅ app/main.py"
echo -e "  ✅ Dockerfile"
echo -e "  ✅ agriculture-iot/docker-compose.yml"
echo -e "  ✅ Certificados SSL generados"
echo -e "  ✅ Repositorio limpio"
echo -e ""
echo -e "${YELLOW}📝 PRÓXIMOS PASOS:${NC}"
echo -e ""
echo -e "1. Hacer commit de los cambios:"
echo -e "   ${BLUE}git add .${NC}"
echo -e "   ${BLUE}git commit -m '🔒 SECURITY: Aplicar correcciones críticas'${NC}"
echo -e ""
echo -e "2. Probar el proyecto:"
echo -e "   ${BLUE}sudo ./setup.sh${NC}"
echo -e ""
echo -e "3. Verificar que funciona:"
echo -e "   ${BLUE}curl http://localhost:8002/health${NC}"
echo -e ""
echo -e "${YELLOW}⚠️  IMPORTANTE:${NC}"
echo -e "   - Revisa el archivo .env y personaliza las credenciales"
echo -e "   - NO subas el archivo .env al repositorio"
echo -e "   - Los certificados SSL son autofirmados (solo desarrollo)"
echo -e ""
echo -e "${BLUE}========================================================${NC}"