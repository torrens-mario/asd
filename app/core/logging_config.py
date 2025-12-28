import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_logging():
    """
    Configurar logging seguro para la aplicación
    
    Security considerations:
    - No logear contraseñas, tokens ni datos sensibles
    - Rotar logs para evitar crecimiento infinito
    - Separar logs de aplicación y acceso
    - Incluir timestamp, level, module
    
    Referencias:
    - OWASP Logging Cheat Sheet
    - CWE-532: Insertion of Sensitive Information into Log File
    """
    # ================= CREACIÓN DE CARPETA =================
    # Define que la carpeta se llamará "logs".
    log_dir = Path("logs")

    # .mkdir: Crea la carpeta.
    # exist_ok=True: Si la carpeta ya existe, no da error (simplemente continúa).
    # Sin esto, el programa fallaría la segunda vez que lo ejecutes.
    log_dir.mkdir(exist_ok=True)
    
    # ================= FORMATO VISUAL =================
    # Define cómo se verá cada línea de texto en el archivo.
    # %(asctime)s: Fecha y hora exacta.
    # %(name)s: Nombre del archivo/módulo que reportó el evento.
    # %(levelname)s: Nivel de gravedad (INFO, WARNING, ERROR).
    # %(message)s: El mensaje que escribiste.
    log_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S' # Formato de fecha: Año-Mes-Dia Hora:Min:Seg
    )
    
    # ================= HANDLER DE ARCHIVO (DISCO) =================
    # Configura el guardado en el archivo físico 'logs/app.log'.
    file_handler = RotatingFileHandler(
        'logs/app.log',             # Ruta del archivo.
        maxBytes=10 * 1024 * 1024,  # Límite de tamaño: 10 Megabytes (10 * 1024 KB * 1024 Bytes).
        backupCount=5,              # Mantiene los últimos 5 archivos llenos, borra los más viejos.
        encoding='utf-8'            # Importante para poder loguear tildes y ñ sin errores.
    )
    # Solo guarda mensajes de nivel INFO o superior (ignora DEBUG).
    file_handler.setLevel(logging.INFO)
    # Le aplica el formato de texto que definimos arriba.
    file_handler.setFormatter(log_format)
    
    # ================= HANDLER DE CONSOLA (PANTALLA) =================
    # Configura la salida en la terminal negra donde ejecutas el servidor.
    # sys.stdout: Salida estándar del sistema.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_format)
    
    # ================= APLICAR CONFIGURACIÓN (ROOT) =================
    # Obtiene el "Logger Raíz", el jefe de todos los loggers de la app.
    root_logger = logging.getLogger()

    # Establece el nivel global en INFO.
    root_logger.setLevel(logging.INFO)

    # "Enchufa" los dos manejadores al sistema principal.
    # Ahora, cada vez que hagas logging.info(), saldrá por archivo Y por pantalla.
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # ================= LIMPIEZA DE RUIDO =================
    # Estas librerías externas hablan mucho. Aquí les decimos que se "callen" un poco.
    
    # uvicorn: El servidor web. Solo avisará si hay WARNINGs, no info de cada petición normal.
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    
    # sqlalchemy: La base de datos. Solo avisará si algo sale mal (WARNING).
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)

    # passlib: Librería de hashing. Solo errores graves (ERROR).
    logging.getLogger("passlib").setLevel(logging.ERROR)
    
    # Mensaje de prueba para confirmar que todo arrancó bien.
    logging.info("Logging configurado correctamente")