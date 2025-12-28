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
import secrets
import logging

logger = logging.getLogger(__name__)

# ================= CONFIGURACIÓN =================
# SECRET_KEY: La llave maestra para firmar tokens. 
# os.getenv intenta leerla del entorno, si no existe, 'secrets.token_urlsafe(32)' genera una aleatoria.
SECRET_KEY = "123345456"
# ALGORITHM: El algoritmo matemático usado para firmar el JWT.
ALGORITHM = "HS256"
# Tiempos de expiración: Lee del entorno (env) o usa valores por defecto (15 min / 7 días).
# int(...): Convierte el texto recibido a número entero.
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# ================= SEGURIDAD (HASHING) =================
# Usamos Argon2 Password Hasher que es el recomendado según OWASP
# Inicializamos el objeto ph (PasswordHasher) con configuración robusta (OWASP).
ph = PasswordHasher(
    time_cost=2,    # Cuánto tiempo (ciclos de CPU) debe tardar (para frenar ataques de fuerza bruta).
    memory_cost=65536,  # Cuánta memoria RAM consume el proceso (64MB), dificulta uso de GPUs hackers.
    parallelism=4,  # Cuántos hilos de procesamiento usa.
    hash_len=32,    # Largo del resultado final.
    salt_len=16     # Largo de la "sal" (dato aleatorio agregado a la password).
)

# Esto define que el token se obtiene de la URL "/auth/login". 
# Sirve principalmente para que la documentación automática (Swagger UI) funcione con el botón "Authorize".
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ================= MODELOS DE DATOS (SCHEMAS) =================
# Clase para estructurar los datos que van DENTRO del token.
class TokenData(BaseModel):
    sub: Optional[str] = None       # Subject (usualmente el username o ID). Opcional.
    role: Optional[str] = "user"    # Rol del usuario, por defecto "user".
    token_type: Optional[str] = "access"    # Tipo de token.

# Clase para estructurar la respuesta que le damos al usuario al loguearse.
class TokenPair(BaseModel):
    access_token: str       # El token de corta duración.
    refresh_token: str      # El token de larga duración para renovar sesión.
    token_type: str = "bearer"  # Tipo estándar de autenticación.

# ================= FUNCIONES CORE =================

# Función para verificar si una contraseña plana coincide con el hash guardado.
# -> bool: Indica que la función devuelve True o False.
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verificar contraseña con Argon2
    
    Soporta migración desde bcrypt:
    - Si el hash es Argon2: usa ph.verify()
    - Si el hash es bcrypt: usa passlib (compatibilidad)
    """
    try:
        # 1. Intentamos verificar usando Argon2 (lo moderno).
        ph.verify(hashed_password, plain_password)
        
        # 2. Si verifica OK, comprobamos si los parámetros de seguridad han cambiado.
        # Si cambiamos la configuración de Argon2, las pass viejas necesitan actualizarse.
        if ph.check_needs_rehash(hashed_password):
            logger.info("La contraseña del hash necesita rehash (parámetros desactualizados)")
            # Aquí idealmente se actualizaría en la base de datos.
        
        return True # Contraseña correcta.
        
    except VerifyMismatchError:
        # Argon2 dice que la contraseña no coincide.
        return False
        
    except InvalidHashError:
        # El hash guardado NO es formato Argon2 (probablemente es una contraseña antigua en bcrypt).
        # Esto es un sistema de migración "en caliente".
        logger.warning("Hash bcrypt detectado, intentando verificación legacy")
        
        # Importamos CryptContext solo aquí para verificar hash antiguo.
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Si la contraseña vieja (bcrypt) coincide:
        if pwd_context.verify(plain_password, hashed_password):
            logger.info("Verificación legacy bcrypt exitosa - debería rehashear")
            # Aquí deberías disparar una actualización a Argon2 en la base de datos.
            return True
        
        return False    # Ni Argon2 ni Bcrypt coincidieron.

# Función simple para crear un hash nuevo desde una contraseña plana.
def get_password_hash(password: str) -> str:
    """
    Hash de contraseña con Argon2id
    
    Argon2id combina Argon2i (resistente a timing attacks) y 
    Argon2d (resistente a GPU cracking)
    """
    return ph.hash(password)    # Usa la config de Argon2 definida arriba.

# ================= GESTIÓN DE TOKENS =================

# Crea el token de acceso (el que se usa en cada petición).
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Crear access token JWT con expiración corta (15 min)
    
    Payload incluye:
    - sub: username
    - role: user/admin
    - exp: timestamp de expiración
    - iat: timestamp de emisión
    - type: "access"
    """
    to_encode = data.copy() # Copia el diccionario para no modificar el original.

    # Calcula cuándo muere el token.
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # IMPORTANTE: Añadir 'exp' al diccionario para que PyJWT lo reconozca
    to_encode.update({"exp": expire, "type": "access"})

    # jwt.encode: Crea el string codificado
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Creado el access token para el usuario: {data.get('sub')}")
    return encoded_jwt

# Dependencia: Obtiene el usuario actual a partir del token.
# token: str = Depends(oauth2_scheme) -> FastAPI extrae el token del Header automáticamente.
def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    """
    Obtener usuario actual desde JWT access token
    
    Dependency de FastAPI para proteger endpoints
    
    Returns:
        dict: {"username": str, "role": str}
    """
    # Llama a nuestra función de decodificar (ver abajo).    
    payload = decode_token(token)

    # Validación extra: Asegurar que es un token de acceso y no de refresco.
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token inválido"
        )
    
    # Extrae datos del payload.
    username: str = payload.get("sub")
    role: str = payload.get("role", "user")
    
    # Si no hay usuario en el token, error.
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Payload de token inválido"
        )
    
    return {"username": username, "role": role}

# ================= CONTROL DE ROLES =================

# Un decorador/función avanzada. Crea una dependencia dinámica.
def require_role(role: str):
    """
    Dependency factory para requerir rol específico
    
    Uso:
        @router.get("/special")
        def special_endpoint(user = Depends(require_role("moderator"))):
            ...
    """
    # Esta función interna ('checker') es la que FastAPI ejecutará realmente.
    # Recibe el 'user' que ya validó 'get_current_user'.
    def checker(user = Depends(get_current_user)):
        # Si el rol del usuario no coincide con el requerido...
        if user["role"] != role:
            # Lanza error 403 (Prohibido).
            raise HTTPException(status_code=403, detail="Privilegios insuficientes")
        return user
    return checker  # Devuelve la función verificadora.

# Crea el token de refresco (para obtener nuevos access tokens sin loguearse de nuevo).
def create_refresh_token(data: dict) -> str:
    """
    Crear refresh token JWT con expiración larga (7 días)
    
    Usado para obtener nuevos access tokens sin re-autenticar
    """
    to_encode = data.copy()
    # Expira en días (ej. 7 días), dura más que el access token.
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),   # 'iat' = Issued At (cuándo se creó).
        "type": "refresh"           # Marca explícitamente que es tipo 'refresh'.
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Creado el refresh token para el usuario: {data.get('sub')}")
    
    return encoded_jwt

# Función auxiliar para decodificar y validar el JWT.
def decode_token(token: str) -> Dict:
    """
    Decodificar y validar token JWT
    
    Raises:
        HTTPException: Si el token es inválido o expirado
    """
    try:
        # jwt.decode verifica la firma usando la SECRET_KEY. Si fue alterado, falla.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
        
    except ExpiredSignatureError: 
        logger.warning("El token ha expirado")
        raise HTTPException(status_code=401, detail="El token ha expirado")
        
    except PyJWTError as e:
        logger.error(f"Error al decodificar JWT: {e}")
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

# Dependencia específica para administradores.
# Reutiliza get_current_user pero añade la capa de validación de rol 'admin'.
def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    """
    Dependency para requerir rol admin
    
    Uso:
        @router.delete("/users/{id}")
        def delete_user(user = Depends(require_admin)):
            ...
    """
    if user["role"] != "admin":
        logger.warning(f"El usuario {user['username']} intentó realizar una acción de administrador sin privilegios")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privilegios de administrador requeridos"
        )
    return user