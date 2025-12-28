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
