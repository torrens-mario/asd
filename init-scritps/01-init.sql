-- Asegurar permisos completos para el usuario
GRANT ALL PRIVILEGES ON DATABASE secure_api_db TO secure_api_user;
GRANT ALL ON SCHEMA public TO secure_api_user;

-- Habilitar extensiones útiles
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Log
DO $$
BEGIN
    RAISE NOTICE '✓ Base de datos inicializada correctamente';
END $$;