/**
 * Lógica de la página de login
 */

// Verificar que no esté ya autenticado
requireGuest();

// Referencias al DOM
const loginForm = document.getElementById('login-form');
const submitButton = loginForm.querySelector('button[type="submit"]');

// Event listener para el formulario
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Limpiar mensajes anteriores
    clearMessages();
    
    // Obtener valores del formulario
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    // Validación básica del lado del cliente
    if (!username || username.length < 3) {
        showMessage('El usuario debe tener al menos 3 caracteres', 'error');
        return;
    }
    
    if (!password || password.length < 8) {
        showMessage('La contraseña debe tener al menos 8 caracteres', 'error');
        return;
    }
    
    // Establecer estado de carga
    setButtonLoading(submitButton, true);
    
    try {
        // Crear FormData para el endpoint de OAuth2
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        
        // Realizar petición al backend
        const response = await fetch(API_BASE + '/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'Credenciales incorrectas');
        }
        
        // Verificar respuesta
        if (data.access_token) {
            // Guardar token
            setStorage('token', data.access_token);
            
            // Obtener información del usuario desde /auth/me
            try {
                const userInfo = await getData('/auth/me');
                setStorage('user', userInfo);
            } catch (error) {
                // Si falla, guardar datos básicos
                setStorage('user', {
                    username: username,
                    role: 'user' // Por defecto
                });
            }
            
            showMessage('Inicio de sesión exitoso. Redirigiendo...', 'success', 2000);
            
            // Redirigir al dashboard después de 2 segundos
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 2000);
        } else {
            throw new Error('Respuesta inválida del servidor');
        }
    } catch (error) {
        console.error('Error en login:', error);
        showMessage(error.message || 'Error al conectar con el servidor', 'error');
        setButtonLoading(submitButton, false);
    }
});

// Focus automático en el campo de usuario
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('username').focus();
});