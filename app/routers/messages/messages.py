from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import SQLModel, create_engine, Session, select
from app.models.asset import Message, User
from app.models.schemas import MessageCreate, MessageOut
from app.core.security import get_current_user
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")
engine = create_engine(DATABASE_URL, echo=False)

# Ensure tables exist
SQLModel.metadata.create_all(engine)

router = APIRouter()

@router.post("/", response_model=MessageOut, status_code=201)
def create_message(payload: MessageCreate, user=Depends(get_current_user)):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.username == user["username"])).first()
        msg = Message(content=payload.content, owner_id=db_user.id)
        session.add(msg)
        session.commit()
        session.refresh(msg)
        return msg

@router.get("/", response_model=list[MessageOut])
def list_my_messages(user=Depends(get_current_user)):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.username == user["username"])).first()
        msgs = session.exec(select(Message).where(Message.owner_id == db_user.id)).all()
        return msgs

@router.delete("/{message_id}", status_code=204)
def delete_message(message_id: int, user=Depends(get_current_user)):
    with Session(engine) as session:
        msg = session.get(Message, message_id)
        if not msg or msg.owner_id != session.exec(select(User).where(User.username == user["username"])).first().id:
            raise HTTPException(status_code=404, detail="Message not found")
        session.delete(msg)
        session.commit()
        return
