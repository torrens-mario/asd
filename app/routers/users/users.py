from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlmodel import Session, select
from typing import List
import logging


from app.models.asset import User
from app.models.schemas import UserOut, UserUpdate
from app.core.security import get_current_user, require_admin
from app.core.database import get_session

logger = logging.getLogger(__name__) # Configurar logger que es usado para registrar eventos en este modulo
router = APIRouter() # Crear un router para las rutas de usuarios

# Ruta para gestionar usuarios
@router.get("/", response_model=List[UserOut]) # Listar usuarios / es para la ruta raiz del router, response_model define el esquema de respuesta y List[UserOut] indica que devuelve una lista de usuarios
def list_users( # Definir la funcion para listar usuarios
    skip: int = Query(0, ge=0), # Parametro de consulta para paginacion, valor por defecto 0, debe ser mayor o igual a 0
    limit: int = Query(100, ge=1, le=500), # Parametro de consulta para limitar resultados, valor por defecto 100, debe estar entre 1 y 500
    current_user: dict = Depends(require_admin), # Dependencia para obtener el usuario actual y verificar que es admin
    session: Session = Depends(get_session), # Dependencia para obtener la sesion de base de datos
):
    """
    Listar todos los usuarios.
    
    RBAC: Solo administradores.
    """
    query = select(User).offset(skip).limit(limit) # Consulta para seleccionar usuarios con paginacion
    users = session.exec(query).all() # Ejecutar la consulta y obtener todos los usuarios
    
    logger.info(f"Admin {current_user['username']} listed {len(users)} users.") # Registrar evento de listado de usuarios
    
    return users # Devolver la lista de usuarios

@router.get("/{user_id}", response_model=List[UserOut]) # Obtener detalles de un usuario por ID
def get_user(
    user_id: int = Path(..., gt=0), # Parametro de ruta para el ID del usuario, debe ser mayor que 0
    current_user: dict = Depends(get_current_user), # Dependencia para obtener el usuario actual
    session: Session = Depends(get_session) # Dependencia para obtener la sesion de base de datos
):
    """
    
    Obtener detalles de un usuario por ID.
    
    RBAC: Administradores pueden ver cualquier usuario; usuarios normales solo pueden ver su propio perfil.
    
    """
    user = session.get(User, user_id) # Obtener el usuario de la base de datos por ID
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="No users found."
            )
    
    #Verificar permisos si no es admin
    if current_user["role"] != "admin": # Si el rol del usuario actual no es admin
        current_user_db = session.exec( # Obtener el usuario actual desde la base de datos
            select(User).where(User.username == current_user["username"]) # Filtrar por nombre de usuario
        ).first() # Obtener el primer resultado
        
        if current_user_db.id != user_id: # Si el ID del usuario actual no coincide con el ID solicitado
            raise HTTPException( # Lanzar excepcion de acceso denegado
                status_code=status.HTTP_403_FORBIDDEN, # Codigo de estado 403 Forbidden
                detail="Access denied." # Detalle del error
            )
            
    return user # Devolver el usuario encontrado

@router.put("/{user_id}", response_model=UserOut) # Actualizar informacion de un usuario por ID
def update_user( # Definir la funcion para actualizar usuario
    user_id: int = Path(..., gt=0), # Parametro de ruta para el ID del usuario, debe ser mayor que 0
    user_data: UserUpdate = ..., # Parametro del cuerpo de la solicitud con los datos a actualizar
    current_user: dict = Depends(require_admin), # Dependencia para verificar que el usuario actual es admin
    session: Session = Depends(get_session) # Dependencia para obtener la sesion de base de datos
):
    """
    Actualizar la informacion de un usuario.
    
    RBAC: Solo administradores.
    """
    user = session.get(User, user_id) # Obtener el usuario de la base de datos por ID
    
    if not user: # Si el usuario no existe, lanzar excepcion
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

# Actualizar solo los campos proporcionados
    update_data = user_data.dict(exclude_unset=True) # Convertir los datos de actualizacion a diccionario, excluyendo campos no establecidos

# Validar email unico si se proporciona
    if "email" in update_data:
        existing = session.exec(
            select(User).where(
                User.email == update_data["email"],
                User.id != user_id
            )
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use."
            )
        

#Prevenir que el ultimo admin se desactive o cambie rol
    if user.role == "admin": # Si el usuario a actualizar es admin
        admin_count = session.exec( # Contar numero de admins activos
            select(func.count(User.id)).where(User.role == "admin", User.is_active == True) # Filtrar por rol admin y estado activo
        ).one() # Obtener el conteo
        
        if admin_count == 1: # Si solo hay un admin activo
            if update_data.get("is_active") is False: # Si se intenta desactivar al ultimo admin
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the last admin user."
                )
            if update_data.get("role") == "user": # Si se intenta cambiar el rol del ultimo admin
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot change role of the last admin user."
                )

    #Aplicar cambios
    for key, value in update_data.items(): # Iterar sobre los datos de actualizacion
        setattr(user, key, value) # Actualizar los atributos del usuario con los nuevos valores
        
    session.add(user) # Agregar el usuario actualizado a la sesion
    session.commit() # Confirmar los cambios en la base de datos    
    session.refresh(user) # Refrescar el objeto usuario desde la base de datos

    logger.info(
        f"Admin {current_user['username']} updated user {user.username}." # Registrar evento de actualizacion de usuario
    )

    return user # Devolver el usuario actualizado

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT) # Eliminar un usuario por ID
def delete_user( # Definir la funcion para eliminar usuario
    user_id: int = Path(..., gt=0), # Parametro de ruta para el ID del usuario, debe ser mayor que 0
    current_user: dict = Depends(require_admin), # Dependencia para verificar que el usuario actual es admin
    session: Session = Depends(get_session) # Dependencia para obtener la sesion de base de datos
):
    """
    Eliminar un usuario.
    
    RBAC: Solo administradores.
    
    VALIDACION: No permitir eliminar al ultimo administrador.
    """
    user = session.get(User, user_id) # Obtener el usuario de la base de datos por ID
    
    if not user: # Si el usuario no existe, lanzar excepcion
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    #Prevenir que el ultimo admin sea eliminado
    if user.role == "admin" : # Si el usuario a eliminar es admin
        admin_count = session.exec( # Contar numero de admins activos
            select(func.count(User.id)).where(User.role == "admin", User.is_active == True) # Filtrar por rol admin y estado activo
        ).one() # Obtener el conteo
        
        if admin_count == 1: # Si solo hay un admin activo
            raise HTTPException( # Lanzar excepcion si se intenta eliminar al ultimo admin
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last admin user."
            )

    #Verificar que el usuario no se este eliminando a si mismo
    current_user_db = session.exec( # Obtener el usuario actual desde la base de datos
        select(User).where(User.username == current_user["username"]) # Filtrar por nombre de
    ).first() # Obtener el primer resultado
    
    if current_user_db.id == user_id: # Si el ID del usuario actual coincide con el ID a eliminar
        raise HTTPException( # Lanzar excepcion si se intenta eliminar a si mismo
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Users cannot delete themselves."
        )
    
    logger.info( # Registrar evento de eliminacion de usuario
                f"Admin {current_user['username']} deleted user {user_id}: {user.username}."
            )
    session.delete(user) # Eliminar el usuario de la sesion
    session.commit() # Confirmar los cambios en la base de datos
    
    return None # Devolver None para indicar que la eliminacion fue exitosa