/**
 * Lógica del dashboard - Gestión de Activos IT
 */

// Verificar autenticación
requireAuth();

// Obtener datos del usuario
let user = getStorage('user');
const token = getStorage('token');

// Estado global
let currentAssetId = null;
let assets = [];
let stats = null;

// Referencias al DOM
const userName = document.getElementById('user-name');
const userRole = document.getElementById('user-role');
const logoutButton = document.getElementById('btn-logout');
const navItems = document.querySelectorAll('.nav-item');
const contentViews = document.querySelectorAll('.content-view');

// Modales
const assetModal = document.getElementById('asset-modal');
const confirmModal = document.getElementById('confirm-modal');

// Botones
const btnNewAsset = document.getElementById('btn-new-asset');
const btnCancelAsset = document.getElementById('btn-cancel-asset');
const btnApplyFilters = document.getElementById('btn-apply-filters');
const btnConfirmYes = document.getElementById('btn-confirm-yes');
const btnConfirmNo = document.getElementById('btn-confirm-no');

// Formulario de activo
const assetForm = document.getElementById('asset-form');

// ========================================
// INICIALIZACIÓN
// ========================================

async function initializeUser() {
    try {
        const userData = await getData('/auth/me');
        
        setStorage('user', userData);
        user = userData;
        
        userName.textContent = userData.username;
        userRole.textContent = userData.role === 'admin' ? 'Administrador' : 'Usuario';
        
        if (userData.role === 'admin') {
            document.querySelectorAll('.admin-only').forEach(el => {
                el.style.display = 'flex';
            });
        }
        
        return userData;
    } catch (error) {
        console.error('Error obteniendo datos del usuario:', error);
        showMessage('Error al cargar datos del usuario', 'error');
        return user;
    }
}

// ========================================
// NAVEGACIÓN ENTRE VISTAS
// ========================================

navItems.forEach(item => {
    item.addEventListener('click', async (e) => {
        e.preventDefault();
        
        const viewName = item.getAttribute('data-view');
        
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        contentViews.forEach(view => view.classList.remove('active'));
        
        const targetView = document.getElementById(`view-${viewName}`);
        if (targetView) {
            targetView.classList.add('active');
        }
        
        if (viewName === 'activos') {
            await loadAssets();
        } else if (viewName === 'estadisticas') {
            await loadStatistics();
        } else if (viewName === 'usuarios') {
            await loadUsers();
        }
        
        window.location.hash = viewName;
    });
});

// ========================================
// GESTIÓN DE ACTIVOS
// ========================================

async function loadAssets() {
    try {
        clearMessages();
        showMessage('Cargando activos...', 'info', 2000);
        
        const filterType = document.getElementById('filter-type')?.value || '';
        const filterStatus = document.getElementById('filter-status')?.value || '';
        const filterRisk = document.getElementById('filter-risk')?.value || '';
        const filterSearch = document.getElementById('filter-search')?.value || '';
        
        let url = '/assets/?skip=0&limit=100';
        if (filterType) url += `&asset_type=${filterType}`;
        if (filterStatus) url += `&status=${filterStatus}`;
        if (filterRisk) url += `&risk_level=${filterRisk}`;
        if (filterSearch) url += `&search=${encodeURIComponent(filterSearch)}`;
        
        assets = await getData(url);
        
        updateAssetsTable();
        
        showMessage(`${assets.length} activos cargados`, 'success', 2000);
    } catch (error) {
        console.error('Error cargando activos:', error);
        showMessage('Error al cargar activos: ' + error.message, 'error');
        document.getElementById('assets-table-body').innerHTML = 
            '<tr><td colspan="8" class="error-message">Error al cargar activos</td></tr>';
    }
}

function updateAssetsTable() {
    const tbody = document.getElementById('assets-table-body');
    
    if (assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="loading">No hay activos registrados</td></tr>';
        return;
    }
    
    tbody.innerHTML = '';
    
    assets.forEach(asset => {
        const tr = document.createElement('tr');
        
        // Nombre
        const tdName = document.createElement('td');
        const strongName = document.createElement('strong');
        strongName.textContent = asset.name;
        tdName.appendChild(strongName);
        if (asset.description) {
            const small = document.createElement('small');
            small.style.display = 'block';
            small.style.color = 'var(--text-secondary)';
            small.textContent = asset.description.substring(0, 50) + (asset.description.length > 50 ? '...' : '');
            tdName.appendChild(small);
        }
        tr.appendChild(tdName);
        
        // Tipo
        const tdType = document.createElement('td');
        const spanType = document.createElement('span');
        spanType.className = 'badge badge-type';
        spanType.textContent = formatAssetType(asset.asset_type);
        tdType.appendChild(spanType);
        tr.appendChild(tdType);
        
        // IP / Hostname
        const tdIp = document.createElement('td');
        if (asset.ip_address) {
            const div = document.createElement('div');
            div.textContent = asset.ip_address;
            tdIp.appendChild(div);
        }
        if (asset.hostname) {
            const small = document.createElement('small');
            small.style.display = 'block';
            small.style.color = 'var(--text-secondary)';
            small.textContent = asset.hostname;
            tdIp.appendChild(small);
        }
        if (!asset.ip_address && !asset.hostname) {
            tdIp.textContent = '-';
        }
        tr.appendChild(tdIp);
        
        // Ubicación
        const tdLocation = document.createElement('td');
        tdLocation.textContent = asset.location || '-';
        tr.appendChild(tdLocation);
        
        // Estado
        const tdStatus = document.createElement('td');
        const spanStatus = document.createElement('span');
        spanStatus.className = `badge badge-status badge-${asset.status}`;
        spanStatus.textContent = formatStatus(asset.status);
        tdStatus.appendChild(spanStatus);
        tr.appendChild(tdStatus);
        
        // Riesgo
        const tdRisk = document.createElement('td');
        const spanRisk = document.createElement('span');
        spanRisk.className = `badge badge-risk badge-${asset.risk_level}`;
        spanRisk.textContent = formatRisk(asset.risk_level);
        tdRisk.appendChild(spanRisk);
        tr.appendChild(tdRisk);
        
        // Propietario
        const tdOwner = document.createElement('td');
        tdOwner.textContent = asset.owner?.username || `ID: ${asset.owner_id}`;
        tr.appendChild(tdOwner);
        
        // Acciones
        const tdActions = document.createElement('td');
        tdActions.className = 'actions-cell';
        
        const currentUser = getStorage('user');
        const isOwner = asset.owner_id === currentUser.id;
        const isAdmin = currentUser.role === 'admin';
        
        if (isOwner || isAdmin) {
            const btnView = document.createElement('button');
            btnView.className = 'btn-action btn-view';
            btnView.textContent = 'Ver';
            btnView.addEventListener('click', () => viewAsset(asset));
            tdActions.appendChild(btnView);
            
            if (isAdmin) {
                const btnEdit = document.createElement('button');
                btnEdit.className = 'btn-action btn-edit';
                btnEdit.textContent = 'Editar';
                btnEdit.addEventListener('click', () => editAsset(asset));
                tdActions.appendChild(btnEdit);
                
                const btnDelete = document.createElement('button');
                btnDelete.className = 'btn-action btn-delete';
                btnDelete.textContent = 'Eliminar';
                btnDelete.addEventListener('click', () => confirmDeleteAsset(asset));
                tdActions.appendChild(btnDelete);
            }
        } else {
            const spanNoAccess = document.createElement('span');
            spanNoAccess.className = 'no-access';
            spanNoAccess.textContent = 'Solo lectura';
            tdActions.appendChild(spanNoAccess);
        }
        
        tr.appendChild(tdActions);
        tbody.appendChild(tr);
    });
}

let myChart = null; // Variable global para guardar la gráfica

function viewAsset(asset) {
    // 1. Abrir el modal
    const modal = document.getElementById('chart-modal');
    document.getElementById('chart-modal-title').textContent = asset.name;
    document.getElementById('chart-modal-desc').textContent = `Ubicación: ${asset.location} | IP: ${asset.ip_address || 'N/A'}`;
    modal.style.display = 'block';

    // 2. Preparar el lienzo (Canvas)
    const ctx = document.getElementById('sensorHistoryChart').getContext('2d');

    // Si ya había una gráfica, la destruimos para no pintar encima
    if (myChart) {
        myChart.destroy();
    }

    // 3. GENERAR DATOS SIMULADOS (Aquí iría el fetch a tu API de historial)
    // Simulamos las últimas 10 horas
    const labels = [];
    const dataPoints = [];
    const now = new Date();
    
    for (let i = 10; i >= 0; i--) {
        // Hora: Ahora menos 'i' horas
        const t = new Date(now.getTime() - (i * 60 * 60 * 1000));
        labels.push(t.getHours() + ":00");
        
        // Dato: Un valor aleatorio cercano al valor actual del sensor
        // Leemos el valor actual de la descripción (ej: "Lectura: 24.5")
        let baseVal = 25; 
        try {
            const match = asset.description.match(/(\d+(\.\d+)?)/);
            if(match) baseVal = parseFloat(match[0]);
        } catch(e) {}

        // Variación aleatoria suave
        dataPoints.push(baseVal + (Math.random() * 4 - 2)); 
    }

    // 4. DIBUJAR LA GRÁFICA
    myChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Temperatura / Valor (°C/%)',
                data: dataPoints,
                borderColor: '#6c5ce7', // Tu color morado
                backgroundColor: 'rgba(108, 92, 231, 0.2)',
                borderWidth: 2,
                tension: 0.4, // Curvas suaves
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: false }
            }
        }
    });
}

function closeChartModal() {
    document.getElementById('chart-modal').style.display = 'none';
}
// ========================================
// CRUD DE ACTIVOS
// ========================================

if (btnNewAsset) {
    btnNewAsset.addEventListener('click', () => {
        currentAssetId = null;
        document.getElementById('asset-modal-title').textContent = 'Nuevo Activo';
        assetForm.reset();
        assetModal.classList.add('show');
    });
}

function editAsset(asset) {
    console.log("Editando activo:", asset); // <--- SE AÑADE ESTO PARA DEPURAR
    currentAssetId = asset.id;
    document.getElementById('asset-modal-title').textContent = 'Editar Activo';
    
    document.getElementById('asset-name').value = asset.name;
    document.getElementById('asset-type').value = asset.asset_type;
    document.getElementById('asset-description').value = asset.description || '';
    document.getElementById('asset-ip').value = asset.ip_address || '';
    document.getElementById('asset-hostname').value = asset.hostname || '';
    document.getElementById('asset-os').value = asset.os_version || '';
    document.getElementById('asset-location').value = asset.location || '';
    document.getElementById('asset-status').value = asset.status;
    document.getElementById('asset-risk').value = asset.risk_level;
    
    assetModal.classList.add('show');
}

assetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const assetData = {
        name: document.getElementById('asset-name').value.trim(),
        asset_type: document.getElementById('asset-type').value,
        description: document.getElementById('asset-description').value.trim() || null,
        ip_address: document.getElementById('asset-ip').value.trim() || null,
        hostname: document.getElementById('asset-hostname').value.trim() || null,
        os_version: document.getElementById('asset-os').value.trim() || null,
        location: document.getElementById('asset-location').value.trim() || null,
        status: document.getElementById('asset-status').value,
        risk_level: document.getElementById('asset-risk').value
    };
    
    try {
        if (currentAssetId) {
            await putData(`/assets/${currentAssetId}`, assetData);
            showMessage('Activo actualizado correctamente', 'success');
        } else {
            await postData('/assets/', assetData);
            showMessage('Activo creado correctamente', 'success');
        }
        
        assetModal.classList.remove('show');
        await loadAssets();
    } catch (error) {
        console.error('Error guardando activo:', error);
        showMessage('Error al guardar activo: ' + error.message, 'error');
    }
});

if (btnCancelAsset) {
    btnCancelAsset.addEventListener('click', () => {
        assetModal.classList.remove('show');
    });
}

function confirmDeleteAsset(asset) {
    currentAssetId = asset.id;
    document.getElementById('confirm-message').textContent = 
        `¿Estás seguro de eliminar el activo "${asset.name}"? Esta acción no se puede deshacer.`;
    confirmModal.classList.add('show');
}

btnConfirmYes.addEventListener('click', async () => {
    try {
        await deleteData(`/assets/${currentAssetId}`);
        showMessage('Activo eliminado correctamente', 'success');
        confirmModal.classList.remove('show');
        await loadAssets();
    } catch (error) {
        console.error('Error eliminando activo:', error);
        showMessage('Error al eliminar activo: ' + error.message, 'error');
    }
});

btnConfirmNo.addEventListener('click', () => {
    confirmModal.classList.remove('show');
});

if (btnApplyFilters) {
    btnApplyFilters.addEventListener('click', async () => {
        await loadAssets();
    });
}

// ========================================
// ESTADÍSTICAS
// ========================================

async function loadStatistics() {
    try {
        clearMessages();
        showMessage('Cargando estadísticas...', 'info', 2000);
        
        stats = await getData('/assets/stats');
        
        document.getElementById('stat-total-assets').textContent = stats.total_assets;
        document.getElementById('stat-active-assets').textContent = stats.by_status?.active || 0;
        document.getElementById('stat-critical-assets').textContent = stats.critical_assets;
        
        renderChart('chart-by-type', stats.by_type, 'Tipo');
        renderChart('chart-by-status', stats.by_status, 'Estado');
        renderChart('chart-by-risk', stats.by_risk_level, 'Riesgo');
        
        showMessage('Estadísticas cargadas', 'success', 2000);
    } catch (error) {
        console.error('Error cargando estadísticas:', error);
        showMessage('Error al cargar estadísticas: ' + error.message, 'error');
    }
}

function renderChart(containerId, data, label) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    container.innerHTML = '';
    
    const total = Object.values(data).reduce((sum, val) => sum + val, 0);
    
    for (const [key, value] of Object.entries(data)) {
        const percentage = total > 0 ? (value / total * 100).toFixed(1) : 0;
        
        const barWrapper = document.createElement('div');
        barWrapper.className = 'chart-bar-wrapper';
        
        const barLabel = document.createElement('div');
        barLabel.className = 'chart-bar-label';
        barLabel.textContent = `${formatLabel(key)}: ${value}`;
        
        const barContainer = document.createElement('div');
        barContainer.className = 'chart-bar-container';
        
        const bar = document.createElement('div');
        bar.className = 'chart-bar';
        bar.style.width = `${percentage}%`;
        bar.textContent = `${percentage}%`;
        
        barContainer.appendChild(bar);
        barWrapper.appendChild(barLabel);
        barWrapper.appendChild(barContainer);
        container.appendChild(barWrapper);
    }
}

// ========================================
// GESTIÓN DE USUARIOS (solo admin)
// ========================================

async function loadUsers() {
    const container = document.getElementById('users-container');
    
    const currentUser = getStorage('user');
    if (currentUser.role !== 'admin') {
        container.innerHTML = '<p class="error-message">⛔ No tienes permisos para ver esta sección</p>';
        return;
    }
    
    try {
        const users = await getData('/users/');
        
        let html = `
            <table class="users-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Email</th>
                        <th>Rol</th>
                        <th>Estado</th>
                        <th>Fecha Registro</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        users.forEach(u => {
            html += `
                <tr>
                    <td>${u.id}</td>
                    <td><strong>${sanitizeHTML(u.username)}</strong></td>
                    <td>${sanitizeHTML(u.email)}</td>
                    <td><span class="badge badge-${u.role}">${u.role === 'admin' ? 'Admin' : 'Usuario'}</span></td>
                    <td>${u.is_active ? '✅ Activo' : '❌ Inactivo'}</td>
                    <td>${formatDate(u.created_at)}</td>
                </tr>
            `;
        });
        
        html += `
                </tbody>
            </table>
        `;
        
        container.innerHTML = html;
    } catch (error) {
        console.error('Error cargando usuarios:', error);
        container.innerHTML = '<p class="error-message">Error al cargar usuarios</p>';
    }
}

// ========================================
// FUNCIONES DE FORMATO
// ========================================

function formatAssetType(type) {
    const types = {
        'server': 'Servidor',
        'workstation': 'Estación de Trabajo',
        'network_device': 'Dispositivo de Red',
        'application': 'Aplicación',
        'database': 'Base de Datos',
        'mobile_device': 'Dispositivo Móvil'
    };
    return types[type] || type;
}

function formatStatus(status) {
    const statuses = {
        'active': 'Activo',
        'inactive': 'Inactivo',
        'maintenance': 'Mantenimiento',
        'decommissioned': 'Fuera de Servicio'
    };
    return statuses[status] || status;
}

function formatRisk(risk) {
    const risks = {
        'low': 'Bajo',
        'medium': 'Medio',
        'high': 'Alto',
        'critical': 'Crítico'
    };
    return risks[risk] || risk;
}

function formatLabel(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// ========================================
// LOGOUT
// ========================================

logoutButton.addEventListener('click', async (e) => {
    e.preventDefault();
    
    try {
        await getData('/auth/logout').catch(() => {});
    } catch (error) {
        console.log('Logout endpoint no disponible');
    }
    
    logout();
});

// ========================================
// INICIALIZACIÓN AL CARGAR
// ========================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log('Dashboard cargado');
    
    await initializeUser();
    
    const hash = window.location.hash.substring(1);
    if (hash === 'estadisticas') {
        document.querySelector('[data-view="estadisticas"]').click();
    } else if (hash === 'usuarios') {
        document.querySelector('[data-view="usuarios"]').click();
    } else {
        await loadAssets();
    }
});