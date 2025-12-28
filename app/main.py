from app.routers.assets import assets
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.messages import messages
from fastapi.middleware.cors import CORSMiddleware # <--- IMPRESCINDIBLE
from fastapi import FastAPI
from app.routers.vulnerabilities import vulnerabilities


# ================= CONFIGURACIÓN INICIAL =================
# Ejecutamos la función de logs que analizamos antes. 
# Si no haces esto, los logs no se guardarán en archivo.
setup_logging()

# Obtenemos el logger para este archivo.
logger = logging.getLogger(__name__)

# Creamos la instancia de la aplicación.
app = FastAPI(
    title="Agriculture IoT API",
    openapi_url="/openapi.json",
    docs_url="/docs",
    # Esto es vital: le dice a Swagger que estamos detrás de /api
    servers=[{"url": "/api", "description": "Nginx Proxy"}, {"url": "/", "description": "Directo"}] 
)

# ================= EVENTOS DEL CICLO DE VIDA =================
# @app.on_event("startup"): Este código se ejecuta UNA SOLA VEZ, justo cuando enciendes el servidor.

# --- CONFIGURACIÓN CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # <--- El asterisco es clave para que te funcione desde el escritorio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    logger.info("Iniciando API de Inventario de Activos...")
    # Llama a la función que crea las tablas en la DB si no existen.
    create_db_and_tables()
    logger.info("API preparada para recibir solicitudes")



app.include_router(assets.router)

# ================= MANEJO DE ERRORES (EXCEPTION HANDLERS) =================
# Estos bloques interceptan errores para que el usuario nunca vea un mensaje feo de código ("Internal Server Error" crudo).

# 1. Error Global (Catch-All): Atrapa cualquier crash inesperado del código.
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exec: Exception):
    # Registramos el error completo en el log para los desarrolladores.
    """
    Manejador global de excepciones no capturadas
    
    Security:
    - NO exponer stack traces al cliente
    - Logear error completo con traceback
    - Devolver mensaje genérico
    
    Referencias:
    - CWE-209: Generation of Error Message Containing Sensitive Information
    - OWASP Top 10 A09:2021 - Security Logging and Monitoring Failures
    """
    logger.error(
        f"Error inesperado en {request.method} {request.url.path}: {exec}",
        exc_info = True, # ¡IMPORTANTE! Esto guarda el "Traceback" (la pila de llamadas) en el log.
        # extra={...}: Agrega datos contextuales al log JSON.
        extra = {
            "client_host": request.client.host if request.client else "unknown",    # IP del cliente.
            "method": request.method,   # GET, POST, etc.
            "path": request.url.path,   # /users/me
            "query_params": str(request.query_params)
        }
    )
    # Al usuario le devolvemos un mensaje genérico por seguridad (no revelamos detalles del error interno).
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Error interno del servidor"}
    )

# 2. Error de Validación: Atrapa cuando Pydantic rechaza datos (ej. email mal formato).
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Logueamos como WARNING (no es un error nuestro, es culpa del cliente).
    """
    Manejador de errores de validación de Pydantic
    
    Security:
    - Devolver errores genéricos (no exponer estructura interna)
    - Logear detalles para debugging
    """
    logger.warning(
        f"Error de validación en {request.method} {request.url.path}: {exc.errors()}",
        extra = {
            "client_host": request.client.host if request.client else "unknown",
            "errors": exc.errors()  # Detalles exactos de qué campo falló.
        }
    )
    # Devolvemos un 422 (Unprocessable Entity).
    return JSONResponse(
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
        content = {"detail": "Petición de datos inválida"}
    )

# 3. Error HTTP Estándar: Atrapa cuando nosotros lanzamos `raise HTTPException(...)`.
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Manejador de excepciones HTTP explícitas
    
    Estas son lanzadas intencionalmente (HTTPException de FastAPI)
    """
    logger.warning(
        f"Error HTTP {exc.status_code} en {request.url.path}: {exc.detail}",
        extra = {"client_host": request.client.host if request.client else "unknown"}
    )
    # Devolvemos exactamente el código y mensaje que definimos al lanzar el error.
    return JSONResponse(
        status_code = exc.status_code,
        content = {"detail": exc.detail}
    )

# ================= RUTAS PRINCIPALES =================
# Endpoint simple para ver si el servidor está vivo (Health Check).
# Útil para balanceadores de carga o Kubernetes
@app.get("/health")
def health():
    return {"status": "ok"}

# Conectamos las "tuberías" de las otras secciones de la app.
# prefix="/auth": Todas las rutas de auth.py empezarán por /auth (ej: /auth/login).
# tags=["auth"]: Las agrupa bajo la etiqueta "auth" en la documentación visual.
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])

# ================= ARRANQUE LOCAL =================
# Este bloque solo se ejecuta si corres el archivo directamente (python main.py).
if __name__ == "__main__":
    import uvicorn  # El servidor web asíncrono.
    # Arranca la app en el puerto 8001.
    # host="0.0.0.0" permite que sea visible desde otras máquinas en la red (o Docker).
    uvicorn.run(app, host="0.0.0.0", port=8001)