from sqlmodel import create_engine, Session, SQLModel
from contextlib import contextmanager
import os
import logging

# Configuración del logger para este archivo específico.
logger = logging.getLogger(__name__)

# ================= CONFIGURACIÓN =================
# DATABASE_URL: La dirección de la base de datos.
# os.getenv busca la variable "DATABASE_URL". Si no existe (ej. en tu PC local),
# usa por defecto "sqlite:///./database/data.db" (una base de datos en archivo local).
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")

# Creación del ENGINE (El Motor).
# Es el objeto global que mantiene las conexiones abiertas listas para usarse.
engine = create_engine(
    DATABASE_URL,
    echo=False,  # IMPORTANTE: Si es True, imprime cada SQL en la consola. False por seguridad y limpieza.
    # connect_args: Configuración específica para SQLite.
    # "check_same_thread": False -> Necesario porque FastAPI usa múltiples hilos
    # y SQLite por defecto se queja si un hilo distinto intenta usar la conexión.
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# ================= FUNCIONES DE INICIALIZACIÓN =================
def create_db_and_tables():
    """
    Crear base de datos y tablas
    
    NOTA: En producción usar Alembic para migraciones
    """
    logger.info("Creando tablas de la base de datos...")
    # SQLModel revisa todos los modelos (clases) que hayas importado en tu proyecto
    # y lanza los comandos "CREATE TABLE IF NOT EXISTS" al motor.
    SQLModel.metadata.create_all(engine)
    logger.info("Tablas de la base de datos creadas correctamente")

# ================= GESTIÓN DE SESIONES (PARA FASTAPI) =================
# Esta función es un GENERADOR. Se usa con Depends(get_session) en las rutas.
def get_session():
    """
    Dependency para obtener sesión de DB en FastAPI
    
    Uso:
        @router.get("/items")
        def get_items(session: Session = Depends(get_session)):
            ...
    """
    # Abre una sesión usando el motor.
    with Session(engine) as session:
        # yield entrega la sesión a la ruta de FastAPI y PAUSA la ejecución aquí.
        yield session
        # Cuando la ruta termina de procesar la petición (o lanza un error),
        # el código se reanuda aquí y el "with" se encarga de cerrar la sesión automáticamente.

# ================= GESTIÓN DE SESIONES (USO MANUAL) =================
# Esta función es para usar la DB *fuera* de las rutas de FastAPI.
# Por ejemplo: en scripts de mantenimiento, tareas en segundo plano o tests.
@contextmanager
def get_session_context():
    """
    Context manager para uso fuera de FastAPI
    
    Uso:
        with get_session_context() as session:
            user = session.get(User, 1)
    """
    session = Session(engine)   # Abre sesión manual.
    try:
        yield session           # Entrega la sesión al bloque "with".
        session.commit()        # Si todo salió bien, GUARDA los cambios permanentemente.
    except Exception:
        session.rollback()      # Si hubo un error, DESHACE cualquier cambio pendiente (seguridad).
        raise                   # Vuelve a lanzar el error para que te enteres.
    finally:    
        session.close()         # Pase lo que pase, CIERRA la conexión para no dejarla colgada.