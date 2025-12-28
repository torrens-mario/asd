# En este archivo implementamos la capa de gestion de vulnerabilidades del sistema, incluyendo endpoints para listar, crear vincular y consultar 
# vulnerabilidades asociadas a activos. Su proposito principal es centralizar toda la logica relacionada con el ciclo de vida de las 
# vulnerabilidades. 
# 
# Se implementa tambien control de acceso para que estos endpoints solo sean accesibles por los administradores del sistema
# 
# Sus principales funcionalidades son: 
#   - Hacer consultas filtradas com paginacion para hacer consultas eficientes
#   - Creacion de nuevas vulnerabilidades con validacion previa
#   - Crear asociaciones entre vulnerabilidades y activos, para vincular estos#

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlmodel import Session, select, or_
from typing import List, Optional
from datetime import datetime, timezone 
import logging

# Usamos solo estas dos importaciones para los modelos y esquemas
from app.models import asset as asset_models
from app.models import schemas as schemas_models
from app.core.security import get_current_user, require_admin
from app.core.database import get_session

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/", response_model=List[schemas_models.VulnerabilityOut])
def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None, min_length=2),
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    query = select(asset_models.Vulnerability)

    if severity:
        query = query.where(asset_models.Vulnerability.severity == severity)

    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            or_(
                asset_models.Vulnerability.cve_id.ilike(search_pattern),
                asset_models.Vulnerability.title.ilike(search_pattern)
            )   
        )

    query = query.offset(skip).limit(limit)
    return session.exec(query).all()

@router.post("/", response_model=schemas_models.VulnerabilityOut, status_code=status.HTTP_201_CREATED)
def create_vulnerability(
    vuln_data: schemas_models.VulnerabilityCreate,
    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session)
):
    existing = session.exec(
        select(asset_models.Vulnerability).where(asset_models.Vulnerability.cve_id == vuln_data.cve_id)
    ).first()

    if existing:
        raise HTTPException(400, f"Vulnerability {vuln_data.cve_id} already exists")
    
    db_vuln = asset_models.Vulnerability(**vuln_data.model_dump())
    session.add(db_vuln)
    session.commit()
    session.refresh(db_vuln)
    logger.info(f"Admin {current_user['username']} created {db_vuln.cve_id}")
    return db_vuln

@router.post("/assets/{asset_id}/vulnerabilities/{vuln_id}", status_code=201)
def link_vulnerability_to_asset(
    asset_id: int = Path(..., gt=0),
    vuln_id: int = Path(..., gt=0),
    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session)
):
    asset = session.get(asset_models.Asset, asset_id)
    if not asset: raise HTTPException(404, "Asset not found")
    
    vuln = session.get(asset_models.Vulnerability, vuln_id)
    if not vuln: raise HTTPException(404, "Vulnerability not found")
    
    existing = session.exec(
        select(asset_models.AssetVulnerability).where(
            asset_models.AssetVulnerability.asset_id == asset_id,
            asset_models.AssetVulnerability.vulnerability_id == vuln_id
        )
    ).first()

    if existing: raise HTTPException(400, "Already Linked")

    link = asset_models.AssetVulnerability(asset_id=asset_id, vulnerability_id=vuln_id)
    session.add(link)

    if vuln.severity == "critical" and asset.risk_level != "critical":
        asset.risk_level = "critical"
        asset.updated_at = datetime.now(timezone.utc)
        session.add(asset)

    session.commit()
    return {"message": "Vulnerability linked successfully"}

@router.get("/assets/{asset_id}/vulnerabilities/", response_model=List[schemas_models.VulnerabilityOut])
def get_asset_vulnerabilities( 
    asset_id: int = Path(..., gt=0),
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    asset = session.get(asset_models.Asset, asset_id)
    if not asset: raise HTTPException(404, "asset not found")
    
    if current_user["role"] != "admin":
        if asset.owner_id != current_user.get("id"): # Simplificado
            raise HTTPException(403, "Access denied")
        
    vulns = session.exec(
        select(asset_models.Vulnerability)
        .join(asset_models.AssetVulnerability)
        .where(asset_models.AssetVulnerability.asset_id == asset_id)
        .order_by(asset_models.Vulnerability.severity.desc())
    ).all()

    return vulns