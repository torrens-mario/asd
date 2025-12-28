/**
 * Utilidades compartidas - Sistema de Inventario de Activos IT
 */

const API_BASE = "/api";  // Cambiar según sea necesario

/**
 * Muestra un mensaje en el contenedor de mensajes
 */
function showMessage(message, type = 'info', duration = 5000) {
    const container = document.getElementById('message-container');
    if (!container) return;
    
    const messageEl = document.createElement('div');
    messageEl.className = `message message-${type}`;
    messageEl.textContent = message;
    
    container.appendChild(messageEl);
    
    if (duration > 0) {
        setTimeout(() => {
            messageEl.style.animation = 'fadeOut 0.3s ease';
            setTimeout(() => messageEl.remove(), 300);
        }, duration);
    }
}

/**
 * Limpia todos los mensajes
 */
function clearMessages() {
    const container = document.getElementById('message-container');
    if (container) container.innerHTML = '';
}

/**
 * Valida un email
 */
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Valida un username
 */
function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,50}$/.test(username);
}

/**
 * Evalúa la fortaleza de una contraseña
 */
function getPasswordStrength(password) {
    let score = 0;
    
    if (!password) return { score: 0, text: 'Muy débil', level: 'weak' };
    
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z\d]/.test(password)) score++;
    
    score = Math.min(Math.floor(score / 2), 3);
    
    const strengths = {
        0: { text: 'Muy débil', level: 'weak' },
        1: { text: 'Débil', level: 'weak' },
        2: { text: 'Media', level: 'medium' },
        3: { text: 'Fuerte', level: 'strong' }
    };
    
    return strengths[score];
}

/**
 * Sanitiza HTML para prevenir XSS
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Realiza petición POST
 */
async function postData(url, data) {
    try {
        const response = await fetch(API_BASE + url, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || `Error HTTP: ${response.status}`);
        }
        
        return responseData;
    } catch (error) {
        console.error('Error en petición POST:', error);
        throw error;
    }
}

/**
 * Realiza petición GET
 */
async function getData(url) {
    try {
        const token = getStorage('token');
        
        const response = await fetch(API_BASE + url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            }
        });
        
        if (response.status === 401) {
            // Token inválido o expirado
            logout();
            throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
        }
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || `Error HTTP: ${response.status}`);
        }
        
        return responseData;
    } catch (error) {
        console.error('Error en petición GET:', error);
        throw error;
    }
}

/**
 * Realiza petición PUT
 */
async function putData(url, data) {
    try {
        const token = getStorage('token');
        
        const response = await fetch(API_BASE + url, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            },
            body: JSON.stringify(data)
        });
        
        if (response.status === 401) {
            logout();
            throw new Error('Sesión expirada');
        }
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || `Error HTTP: ${response.status}`);
        }
        
        return responseData;
    } catch (error) {
        console.error('Error en petición PUT:', error);
        throw error;
    }
}

/**
 * Realiza petición DELETE
 */
async function deleteData(url) {
    try {
        const token = getStorage('token');
        
        const response = await fetch(API_BASE + url, {
            method: 'DELETE',
            headers: {
                'Accept': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            }
        });
        
        if (response.status === 401) {
            logout();
            throw new Error('Sesión expirada');
        }
        
        // DELETE puede devolver 204 No Content
        if (response.status === 204) {
            return { success: true };
        }
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || `Error HTTP: ${response.status}`);
        }
        
        return responseData;
    } catch (error) {
        console.error('Error en petición DELETE:', error);
        throw error;
    }
}

/**
 * LocalStorage helpers
 */
function setStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
        console.error('Error guardando en localStorage:', error);
    }
}

function getStorage(key) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : null;
    } catch (error) {
        console.error('Error leyendo de localStorage:', error);
        return null;
    }
}

function removeStorage(key) {
    try {
        localStorage.removeItem(key);
    } catch (error) {
        console.error('Error eliminando de localStorage:', error);
    }
}

function clearStorage() {
    try {
        localStorage.clear();
    } catch (error) {
        console.error('Error limpiando localStorage:', error);
    }
}

/**
 * Verifica autenticación
 */
function isAuthenticated() {
    const token = getStorage('token');
    const user = getStorage('user');
    return token && user && user.username;
}

/**
 * Requiere autenticación
 */
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = 'index.html';
    }
}

/**
 * Requiere ser invitado (no autenticado)
 */
function requireGuest() {
    if (isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }
}

/**
 * Cierra sesión
 */
async function logout() {
    try {
        // Intentar llamar al endpoint de logout si existe
        await getData('/auth/logout').catch(() => {});
    } catch (error) {
        console.log('Logout endpoint no disponible');
    }
    
    clearStorage();
    window.location.href = 'index.html';
}

/**
 * Establece estado de carga en botón
 */
function setButtonLoading(button, loading) {
    const btnText = button.querySelector('.btn-text');
    const btnLoader = button.querySelector('.btn-loader');
    
    if (loading) {
        button.disabled = true;
        if (btnText) btnText.style.display = 'none';
        if (btnLoader) btnLoader.style.display = 'inline';
    } else {
        button.disabled = false;
        if (btnText) btnText.style.display = 'inline';
        if (btnLoader) btnLoader.style.display = 'none';
    }
}

/**
 * Formatea tamaño de archivo
 */
function formatFileSize(mb) {
    if (mb >= 1024) {
        return (mb / 1024).toFixed(2) + ' GB';
    }
    return mb.toFixed(2) + ' MB';
}

/**
 * Formatea fecha
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Añadir estilos de animación
if (!document.querySelector('style[data-utils-styles]')) {
    const style = document.createElement('style');
    style.setAttribute('data-utils-styles', 'true');
    style.textContent = `
        @keyframes fadeOut {
            from { opacity: 1; transform: translateX(0); }
            to { opacity: 0; transform: translateX(-20px); }
        }
    `;
    document.head.appendChild(style);
}