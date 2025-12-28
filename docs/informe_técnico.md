###INFORME TECNICO
## a) Arquitectura del sistema

Basado en la composición del repositorio y las tecnologías detectadas, se propone la siguiente arquitectura lógica:

1. Cliente (Frontend)
   - Tecnologías: HTML, CSS, JavaScript.
   - Función: Interfaz de usuario (UI) para consumo de la API pública/privada.
   - Componentes típicos:
     - Páginas estáticas y SPA (Single Page Application) o vistas renderizadas.
     - Gestión de sesiones y almacenamiento local (localStorage / sessionStorage / cookies).
     - Lógica de llamadas a API (fetch/Axios).

2. API (Backend)
   - Tecnologías: Python (probablemente Flask/FastAPI/Django u otro framework).
   - Función: Proveer endpoints RESTful / GraphQL para la lógica de negocio y acceso a datos.
   - Componentes típicos:
     - Controladores/endpoints.
     - Capa de servicios/negocio.
     - Persistencia (base de datos; no incluida explícitamente en el repo pero asumida).
     - Autenticación y autorización (tokens JWT, OAuth, sesiones).

3. Infraestructura / Entorno de despliegue
   - Dockerfile presente: contenedorización de la aplicación.
   - Shell scripts: tareas de despliegue/CI / scripts auxiliares.
   - Posible orquestación/hosting (no detectada explícitamente, pero se recomienda Docker + CI/CD).

4. Integración y herramientas
   - Integraciones externas: APIs externas, servicios de autenticación, almacenamiento de terceros.
   - Herramientas de desarrollo: linters, pruebas unitarias, escáneres (recomendado).

Flujo de datos (resumen):
Cliente -> (HTTPS) -> API Python -> Base de datos / servicios externos
Despliegue: fuente -> build (Docker) -> entorno (staging/production)

Recomendación arquitectónica breve:
- Separar claramente frontend estático y backend en microservicios o contenedores distintos.
- Añadir un proxy inverso (nginx) para manejar TLS, cabeceras y rate limiting.
- Monitorización y logging centralizado (e.g., Prometheus + Grafana / ELK).

---

## b) Controles de seguridad en el frontend

Controles recomendados (priorizados):

1. Comunicación segura
   - HTTPS obligatorio (HSTS en servidor).
   - Rechazar recursos desde HTTP mixto.

2. Content Security Policy (CSP)
   - Definir CSP restrictiva evitando `unsafe-inline` y `unsafe-eval`.
   - Permitir solo dominios necesarios para scripts, estilos y recursos.

3. Protección contra XSS
   - Escapar/sanitizar cualquier dato que se inserte en el DOM.
   - Usar APIs seguras (textContent, innerText) en lugar de innerHTML cuando sea posible.
   - SRI (Subresource Integrity) para scripts/estilos cargados de CDN.

4. Manejo seguro de tokens y credenciales
   - No almacenar tokens de larga duración en localStorage si pueden ser vulnerables a XSS.
   - Preferir cookies HttpOnly + Secure + SameSite=strict para sesiones, cuando el backend lo permita.
   - Si se usan tokens en JS (ej. JWT), minimizar su tiempo de vida y refrescarlos mediante refresh tokens almacenados de forma segura.

5. Protección CSRF
   - Si se usan cookies para autenticación, implementar tokens CSRF (double submit cookie o token en cabeceras).
   - Para APIs autenticadas con tokens en cabecera (Authorization: Bearer), CSRF es menos crítico pero verificar.

6. Validación y sanitización en cliente
   - Validación preliminar en frontend para UX, pero siempre replicar validación en backend (no confiar en el cliente).
   - Limitar tamaño de carga y tipos MIME permitidos.

7. Gestión de dependencias y build
   - Lockfiles (package-lock.json / yarn.lock).
   - Escanear dependencias por vulnerabilidades (npm audit, Snyk, GitHub Dependabot).
   - Minimizar inclusión de librerías innecesarias.

8. Cabeceras HTTP desde frontend/backend
   - X-Frame-Options, X-Content-Type-Options: nosniff, Referrer-Policy.
   - HSTS y Strict-Transport-Security configurados en servidor.

9. Manejo de errores y logging
   - No exponer stack traces ni información sensible en la UI.
   - Enviar logs sanitizados a servicios de monitoreo.

10. Testing y automatización
   - Pruebas E2E y unitarias que verifiquen controles de seguridad (inyección, XSS, autenticación).

---

## c) Integración con API

Buenas prácticas de integración cliente ↔ API:

1. Autenticación y autorización
   - Flujos recomendados:
     - OAuth 2.0 / OpenID Connect para integración con proveedores.
     - JWT con short-lived access tokens + refresh tokens (refresh tokens almacenados en HttpOnly cookies).
   - Roles y scopes en los claims del token para autorización granular.

2. Llamadas y manejo de estado
   - Usar fetch/axios con control de timeouts, reintentos exponenciales (solo para idempotentes).
   - Manejo consistente de códigos de estado HTTP:
     - 2xx → procesar respuesta
     - 4xx → mostrar errores de usuario o re-autenticación
     - 5xx → reintentar con backoff o mostrar error genérico

3. CORS
   - Configurar Cross-Origin Resource Sharing en el servidor permitiendo sólo orígenes confiables.
   - No usar Access-Control-Allow-Origin: * para APIs que requieren autenticación.

4. Contratos y versión de API
   - Versionado: /api/v1/...
   - Documentación Swagger/OpenAPI para facilitar integraciones y pruebas.

5. Validación y límites
   - Validar payloads en backend (esquemas JSON Schema / Pydantic).
   - Rate limiting: por IP / por usuario.
   - Throttling y protección contra abuse.

6. Seguridad adicional en transporte
   - TLS 1.2+ con suites seguras.
   - Certificados gestionados (Let’s Encrypt / ACM).

7. Manejo de errores y observabilidad
   - Respuestas con mensajes controlados para evitar fuga de información.
   - Trazabilidad: request-id en cabeceras para correlacionar logs.

8. Pruebas de integración
   - Tests que verifiquen autenticación, autorización, límites y errores.

Ejemplo de patrón de llamada (resumido):
- Cliente obtiene access token (o cookie HttpOnly con sesión).
- Requests incluyen Authorization: Bearer <token> o confían en cookie HttpOnly.
- Backend valida token y aplica control de acceso.
- Backend responde JSON consistente y con códigos HTTP adecuados.

---

## d) Checklist OWASP Top 10 (orientado al frontend y la integración con la API)

A continuación un checklist accionable. Marcar cada ítem con [ ] o [x] según su estado (pendiente / realizado). Para cada riesgo se indica mitigaciones y pruebas recomendadas.

- A01:2021 — Broken Access Control
  - [ ] Revisar endpoints y políticas de autorización por rol.
  - Mitigación: Validar autorización en servidor (no confiar en ocultación en frontend).
  - Pruebas: Intentar acceder a recursos con tokens/roles diferentes; forzar IDOR (modificar identificadores).
  - Prioridad: Alta

- A02:2021 — Cryptographic Failures (exposición de datos)
  - [ ] TLS configurado y válido (HSTS activo).
  - [ ] Tokens con expiración corta; refresh controlado.
  - Mitigación: Encriptación en tránsito y en reposo; no guardar secretos en frontend.
  - Pruebas: Verificar certificados, intento de downgrade TLS, revisar almacenamiento local.
  - Prioridad: Alta

- A03:2021 — Injection (incl. XSS)
  - [ ] Validación/sanitización de entradas en frontend y backend.
  - [ ] Escapado de datos en el DOM y uso de APIs seguras.
  - Mitigación: Prepared statements en backend, escapar outputs en frontend.
  - Pruebas: Pruebas XSS reflejado/almacenado, inyección en parámetros.
  - Prioridad: Alta

- A04:2021 — Insecure Design
  - [ ] Revisar modelo de amenazas y diseño seguro (autenticación, autorización, validación).
  - Mitigación: Threat modeling, diseño por capas, principios de menor privilegio.
  - Pruebas: Revisiones de arquitectura y code review centrado en seguridad.
  - Prioridad: Media-Alta

- A05:2021 — Security Misconfiguration
  - [ ] Revisar cabeceras HTTP (CSP, X-Frame-Options, X-Content-Type-Options).
  - [ ] Configuración de CORS mínima necesaria.
  - Mitigación: Harden servers, deshabilitar endpoints de debugging en producción.
  - Pruebas: Scans automáticos (OWASP ZAP), revisión manual de cabeceras.
  - Prioridad: Alta

- A06:2021 — Vulnerable and Outdated Components
  - [ ] Escanear dependencias JS/Python (Dependabot / Snyk / pip-audit).
  - [ ] Mantener lockfiles actualizados.
  - Mitigación: Actualizaciones regulares y políticas de dependencia segura.
  - Pruebas: auditorías automáticas y revisión de CVEs.
  - Prioridad: Alta

- A07:2021 — Identification and Authentication Failures
  - [ ] Implementar protección contra fuerza bruta (rate limit, captchas donde aplique).
  - [ ] Revisar expiración de tokens y revocación (logout efectivo).
  - Mitigación: MFA para zonas sensibles.
  - Pruebas: Intentos de login automatizados, reuso de tokens.
  - Prioridad: Alta

- A08:2021 — Software and Data Integrity Failures
  - [ ] Verificar integridad de builds y dependencias (SRI, firmas).
  - Mitigación: Firmado de artefactos y verificación en pipeline.
  - Pruebas: Simular modificación de assets; verificar integridad SRI.
  - Prioridad: Media

- A09:2021 — Security Logging and Monitoring Failures
  - [ ] Implementar logging de eventos de seguridad sin incluir datos sensibles.
  - [ ] Alertas para patrones anómalos (picos de 401/429/500).
  - Mitigación: Centralización de logs y retención adecuada.
  - Pruebas: Revisar que eventos de fallo y acceso sean registrados correctamente.
  - Prioridad: Media

- A10:2021 — Server-Side Request Forgery (SSRF) / Insufficient Logging (según contexto)
  - [ ] Validar URIs y restricciones de salida si la API hace peticiones a terceros.
  - Mitigación: Lista de permitidos (allowlist) para recursos externos.
  - Pruebas: Intentar peticiones a recursos internos desde endpoints que aceptan URLs.
  - Prioridad: Media

Checklist condensado (para usar en PRs / revisiones):
- [✔️] HTTPS + HSTS activo
- [✔️] CSP aplicada (sin 'unsafe-inline')
- [✔️] Cookies sensibles: HttpOnly, Secure, SameSite
- [✔️] Tokens: corto tiempo de vida y refresh seguro
- [✔️] Validación en cliente y servidor
- [✔️] CORS restrictivo
- [✔️] Escaneo de dependencias automatizado
- [✔️] Rate limiting y protección brute-force
- [✔️] No exponer stacktraces ni secretos en UI
- [✔️] Logging y alertas de seguridad
