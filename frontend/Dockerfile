# Dockerfile para Frontend (NGINX estático)
FROM nginx:alpine

# Metadatos
LABEL maintainer="miguel@example.com"
LABEL description="Frontend para Sistema de Inventario de Activos IT"

# Copiar archivos HTML, CSS, JS al directorio de NGINX
COPY index.html /usr/share/nginx/html/
COPY register.html /usr/share/nginx/html/
COPY dashboard.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/

# Copiar configuración personalizada de NGINX
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Crear usuario no-root para NGINX
RUN addgroup -g 1001 -S nginx-custom && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx-custom -g nginx-custom nginx-custom

# Ajustar permisos
RUN chown -R nginx-custom:nginx-custom /usr/share/nginx/html && \
    chown -R nginx-custom:nginx-custom /var/cache/nginx && \
    chown -R nginx-custom:nginx-custom /var/log/nginx && \
    chown -R nginx-custom:nginx-custom /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx-custom:nginx-custom /var/run/nginx.pid

# Cambiar a usuario no-root
USER nginx-custom

# Exponer puerto 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

# Comando por defecto
CMD ["nginx", "-g", "daemon off;"]