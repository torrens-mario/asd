from fastapi import APIRouter, HTTPException, Depends, Body, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from typing import Dict
from app.models.asset import User
from app.models.schemas import UserCreate, UserOut, TokenPair
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
from app.core.database import get_session
import logging

# Configuración del logger para este archivo.
logger = logging.getLogger(__name__)

# Creamos el Router. En el archivo main.py principal, seguramente harás algo como:
# app.include_router(auth_router)
router = APIRouter()

# ================= RUTA: REGISTRO =================
# @router.post: Define que esta función responde a peticiones HTTP POST en "/register".
# response_model=UserOut: Filtra la respuesta. Aunque creemos un usuario con password, 
# el modelo 'UserOut' se asegura de devolver solo los datos públicos (id, email, username) y no el hash.
@router.post("/register", response_model=UserOut, status_code=201)
def register(user: UserCreate, session: Session = Depends(get_session)):
    # user: UserCreate -> FastAPI valida que el JSON recibido cumpla las reglas (largo, caracteres, etc).
    # session: Session -> FastAPI inyecta una conexión activa a la DB.
    """
    Registrar nuevo usuario
    
    Validaciones automáticas (Pydantic):
    - Username: 3-50 chars, alfanumérico
    - Email: formato válido
    - Password: 8+ chars, mayúsculas, minúsculas, números, símbolos
    
    Security:
    - Password hasheada con Argon2id
    - Rate limited (implementado en main.py)
    """
    # 1. Verificar si el username ya existe.
    # session.exec(select(...)): Ejecuta una consulta SQL SELECT * FROM user WHERE ...
    existing_user = session.exec(
        select(User).where(User.username == user.username)
    ).first()   # .first() devuelve el primer resultado o None.
    
    # Si existe, lanzamos error 400 (Bad Request).
    if existing_user:
        logger.warning(f"Intento de registro con nombre de usuario existente: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de usuario ya registrado"
        )
    
    # 2. Verificar si el email ya existe (misma lógica).
    existing_email = session.exec(
        select(User).where(User.email == user.email)
    ).first()
    
    if existing_email:
        logger.warning(f"Intento de registro con email existente: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email ya registrado"
        )
    
    # 3. Crear el objeto Usuario para la base de datos.
    # ¡OJO! Aquí usamos 'get_password_hash' para convertir "123456" en el hash seguro de Argon2.
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        role="user",  # Por defecto, todos los nuevos usuarios son "user"
        is_active=True  # Por defecto, el usuario está activo
    )
    
    # 4. Guardar en DB.
    session.add(db_user)    # Marca el objeto para ser guardado.
    session.commit()        # Ejecuta la transacción SQL (INSERT INTO...).
    session.refresh(db_user)    # Recarga el objeto desde la DB para obtener el ID autogenerado.
    
    logger.info(f"Nuevo usuario registrado: {user.username} (ID: {db_user.id})")
    
    # Devolvemos el objeto. FastAPI filtrará los campos usando 'response_model=UserOut'.
    return db_user

# ================= RUTA: LOGIN =================
# Devuelve un TokenPair (access + refresh).
@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    session: Session = Depends(get_session)
):
    # form_data: Recibe los datos del formulario estándar (username, password).
    """
    Iniciar sesión con username/password
    
    Devuelve:
    - access_token: JWT válido por 15 minutos
    - refresh_token: JWT válido por 7 días
    
    Security:
    - Rate limited: 5 intentos/minuto (implementado en main.py)
    - Mensajes de error genéricos (no revelar si username existe)
    - Logging de intentos fallidos
    """
    # Buscamos al usuario por nombre.
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    # Verificamos dos cosas:
    # 1. ¿Existe el usuario? (if not user)
    # 2. ¿Coincide la contraseña? (verify_password usa Argon2 para comparar)
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Fallo de login para usuario: {form_data.username}", extra={"username": form_data.username})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Bloqueo extra: Si el usuario existe pero está marcado como inactivo (soft delete).    
    if not user.is_active:
        logger.warning(f"Intento de login con cuenta inactiva: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cuenta inactiva",
        )
    # Preparamos los datos mínimos para meter dentro del token.
    token_data = {"sub": user.username, "role": user.role}

    # Generamos los dos tokens criptográficos.
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info(f"Usuario logueado exitosamente: {user.username} (role: {user.role})")

    # Devolvemos el JSON con los tokens.
    return TokenPair(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

# ================= RUTA: REFRESH TOKEN =================
# Esta ruta se usa cuando el Access Token caduca (pasan los 15 min).
@router.post("/refresh", response_model=Dict[str, str])
def refresh_access_token(refresh_token: str = Body(..., embed=True), session: Session = Depends(get_session)):
    # Body(..., embed=True): Espera un JSON así: { "refresh_token": "el_token_largo..." }
    """
    Renovar access token usando refresh token
    
    Flow:
    1. Cliente detecta que access token expirará pronto
    2. Envía refresh token
    3. Backend valida y genera nuevo access token
    4. Cliente actualiza token sin interrumpir sesión
    
    Security:
    - Valida que el token sea de tipo "refresh"
    - Verifica que el usuario aún exista y esté activo
    - No renueva el refresh token (usar rotation en producción)
    """
    try:
        # Decodificamos el token (verifica firma y expiración de 7 días).
        payload = decode_token(refresh_token)
        
        # Seguridad extra: asegurar que NO estamos intentando usar un Access Token para refrescar.
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Extraemos datos.
        username = payload.get("sub")
        role = payload.get("role", "user")
        
        # Validamos contra la base de datos por si el usuario fue borrado en los últimos días.
        user = session.exec(
            select(User).where(User.username == username)
        ).first()
        
        if not user or not user.is_active:
            logger.warning(f"Refresh attempt for non-existent/inactive user: {username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Creamos UNICAMENTE un nuevo access token. 
        # (Opcionalmente podrías rotar también el refresh token aquí para máxima seguridad).
        new_access_token = create_access_token({"sub": username, "role": role})
        
        logger.info(f"Token refreshed for user: {username}")
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise   # Si ya lanzamos un error HTTP arriba, déjalo pasar.
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

# ================= RUTA: LOGOUT =================
# Nota: JWT es "stateless". El servidor no "recuerda" sesiones abiertas.
# El logout real consiste en que el Frontend (Cliente) borre el token de su memoria.
# Este endpoint es más simbólico o para logs, a menos que implementes una "lista negra" de tokens en DB.
@router.get("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """
    Cerrar sesión
    
    En esta implementación es stateless (solo logging).
    
    En producción:
    - Añadir token a blacklist (Redis)
    - Revocar refresh token
    - Invalidar sesiones activas
    """
    logger.info(f"Usuario {current_user['username']} ha cerrado sesión")
    return {"message": "Logout exitoso"}

# ================= RUTA: ME (PERFIL) =================
# Devuelve los datos del usuario logueado actualmente.
@router.get("/me", response_model=UserOut)
def get_current_user_info(current_user: dict = Depends(get_current_user), session: Session = Depends(get_session)):
    # 1. 'get_current_user' valida el token del header Authorization y devuelve el dict básico.
    
    # 2. Hacemos query a DB para obtener los detalles frescos (email, fecha creación, etc).
    """
    Obtener información del usuario actual
    
    Útil para que el frontend verifique el token y obtenga datos actualizados
    """
    user = session.exec(select(User).where(User.username == current_user["username"])).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user