"""
Router para la gestión de activos, funciona
como un CRUD completo con funcionalidades de
filtrado, paginación y estadísticas. Usando
FastAPI y SQLModel.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlmodel import Session, select, func, or_
from typing import List, Optional
from datetime import datetime
import logging

from app.models.asset import Asset, User, AssetStatus, AssetType, RiskLevel
from app.models.schemas import (
    AssetCreate,
    AssetUpdate,
    AssetOut,
    AssetOutWithOwner,
    AssetStats,
)
from app.core.security import get_current_user, require_admin
from app.core.database import get_session

logger = logging.getLogger(__name__)
router = APIRouter()

# === HELPER FUNCTION ===


def get_current_user_from_db(
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> User:
    """Helper para obtener el usuario completo desde la DB"""
    user = session.exec(
        select(User).where(User.username == current_user["username"])
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return user


# === ENDPOINTS ===


@router.get("/", response_model=List[AssetOut])
def list_assets(
    skip: int = Query(0, ge=0, description="Registros a saltar"),
    limit: int = Query(100, ge=1, le=500, description="Máximo de registros"),
    asset_type: Optional[str] = Query(None, description="Filtrar por tipo"),
    status: Optional[str] = Query(None, description="Filtrar por estado"),
    risk_level: Optional[str] = Query(None, description="Filtrar por nivel de riesgo"),
    search: Optional[str] = Query(
        None, min_length=2, description="Buscar en nombre/hostname"
    ),
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Listar activos con filtros y paginación

    RBAC:
    - Admin: Ve todos los activos
    - User: Solo ve sus activos asignados
    """
    # Query base
    query = select(Asset)

    # Filtrar por owner si no es admin (IDOR protection)
    if current_user["role"] != "admin":
        user = session.exec(
            select(User).where(User.username == current_user["username"])
        ).first()
        query = query.where(Asset.owner_id == user.id)

    # Aplicar filtros opcionales
    if asset_type:
        try:
            AssetType(asset_type)
            query = query.where(Asset.asset_type == asset_type)
        except ValueError:
            raise HTTPException(400, f"Invalid asset_type: {asset_type}")

    if status:
        try:
            AssetStatus(status)
            query = query.where(Asset.status == status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")

    if risk_level:
        try:
            RiskLevel(risk_level)
            query = query.where(Asset.risk_level == risk_level)
        except ValueError:
            raise HTTPException(400, f"Invalid risk_level: {risk_level}")

    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            or_(Asset.name.ilike(search_pattern), Asset.hostname.ilike(search_pattern))
        )

    # Aplicar paginación
    query = query.offset(skip).limit(limit)

    assets = session.exec(query).all()

    logger.info(f"User {current_user['username']} listed {len(assets)} assets")

    return assets


@router.get("/stats", response_model=AssetStats)
def get_asset_statistics(
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Obtener estadísticas de activos

    RBAC:
    - Admin: Estadísticas globales
    - User: Estadísticas solo de sus activos
    """
    query = select(Asset)

    # Filtrar por owner si no es admin
    if current_user["role"] != "admin":
        user = session.exec(
            select(User).where(User.username == current_user["username"])
        ).first()
        query = query.where(Asset.owner_id == user.id)

    # Total de activos
    total_assets = session.exec(
        select(func.count(Asset.id)).select_from(query.subquery())
    ).one()

    # Agrupar por tipo
    by_type_query = (
        select(Asset.asset_type, func.count(Asset.id))
        .select_from(query.subquery())
        .group_by(Asset.asset_type)
    )
    by_type = {str(row[0]): row[1] for row in session.exec(by_type_query).all()}

    # Agrupar por estado
    by_status_query = (
        select(Asset.status, func.count(Asset.id))
        .select_from(query.subquery())
        .group_by(Asset.status)
    )
    by_status = {str(row[0]): row[1] for row in session.exec(by_status_query).all()}

    # Agrupar por nivel de riesgo
    by_risk_query = (
        select(Asset.risk_level, func.count(Asset.id))
        .select_from(query.subquery())
        .group_by(Asset.risk_level)
    )
    by_risk_level = {str(row[0]): row[1] for row in session.exec(by_risk_query).all()}

    # Activos críticos
    critical_query = query.where(Asset.risk_level == RiskLevel.CRITICAL)
    critical_assets = session.exec(
        select(func.count(Asset.id)).select_from(critical_query.subquery())
    ).one()

    return AssetStats(
        total_assets=total_assets,
        by_type=by_type,
        by_status=by_status,
        by_risk_level=by_risk_level,
        critical_assets=critical_assets,
    )


@router.get("/{asset_id}", response_model=AssetOutWithOwner)
def get_asset(
    asset_id: int = Path(..., gt=0),
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Obtener detalle de un activo

    RBAC:
    - Admin: Puede ver cualquier activo
    - User: Solo puede ver sus propios activos
    """
    asset = session.get(Asset, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found"
        )

    # Verificar ownership si no es admin
    if current_user["role"] != "admin":
        user = session.exec(
            select(User).where(User.username == current_user["username"])
        ).first()

        if asset.owner_id != user.id:
            logger.warning(
                f"User {current_user['username']} attempted to access asset {asset_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this asset",
            )

    logger.info(f"User {current_user['username']} accessed asset {asset_id}")

    return asset


@router.post("/", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_data: AssetCreate,
    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session),
):
    """
    Crear nuevo activo

    RBAC: Solo administradores
    """
    # Determinar owner
    if asset_data.owner_id is None:
        creator = session.exec(
            select(User).where(User.username == current_user["username"])
        ).first()
        owner_id = creator.id
    else:
        # Verificar que el owner existe
        owner = session.get(User, asset_data.owner_id)
        if not owner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Owner user with ID {asset_data.owner_id} not found",
            )
        owner_id = asset_data.owner_id

    # Crear activo
    db_asset = Asset(**asset_data.dict(exclude={"owner_id"}), owner_id=owner_id)

    session.add(db_asset)
    session.commit()
    session.refresh(db_asset)

    logger.info(
        f"Admin {current_user['username']} created asset {db_asset.id}: {db_asset.name}"
    )

    return db_asset


@router.put("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int = Path(..., gt=0),
    asset_data: AssetUpdate = ...,
    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session),
):
    """
    Actualizar activo existente

    RBAC: Solo administradores
    """
    asset = session.get(Asset, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found"
        )

    # Actualizar solo campos proporcionados
    update_data = asset_data.dict(exclude_unset=True)

    # Validar owner_id si se proporciona
    if "owner_id" in update_data and update_data["owner_id"] is not None:
        owner = session.get(User, update_data["owner_id"])
        if not owner:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Owner user with ID {update_data['owner_id']} not found",
            )

    # Aplicar cambios
    for key, value in update_data.items():
        setattr(asset, key, value)

    # Actualizar timestamp
    asset.updated_at = datetime.utcnow()

    session.add(asset)
    session.commit()
    session.refresh(asset)

    logger.info(f"Admin {current_user['username']} updated asset {asset_id}")

    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int = Path(..., gt=0),
    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session),
):
    """
    Eliminar activo

    RBAC: Solo administradores
    """
    asset = session.get(Asset, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found"
        )

    logger.warning(
        f"Admin {current_user['username']} deleted asset {asset_id}: {asset.name}"
    )

    session.delete(asset)
    session.commit()

    return None
