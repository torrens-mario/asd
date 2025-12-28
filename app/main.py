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
