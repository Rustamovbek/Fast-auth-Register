
from typing import Annotated
from datetime import timedelta

from fastapi import FastAPI, HTTPException, status, Depends, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database import engine, SessionLocal
from core.auth import (
    get_current_user,
    authenticate_user,
    create_access_token,
    bcrypt_context
)
from models import user
from models.user import User
from schemas.user import CreateUserFrom, Token

app = FastAPI()

user.Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DBSessionDep = Annotated[Session, Depends(get_db)]
CurrentUserDep = Annotated[dict, Depends(get_current_user)]

# Auth router (yo‘llar guruhi)
auth_router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


@auth_router.get("/user", status_code=status.HTTP_200_OK)
async def get_authenticated_user(
        current_user: CurrentUserDep
):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentifikatsiyadan o‘tish muvaffaqiyatsiz bo‘ldi"  # noqa
        )
    return {"foydalanuvchi": current_user}  # noqa


@auth_router.post("/", status_code=status.HTTP_201_CREATED)
async def register_user(
        db: DBSessionDep,
        create_user_request: CreateUserFrom
):
    existing_user = db.query(User).filter(User.username == create_user_request.username).first()  # noqa
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bu foydalanuvchi nomi allaqachon mavjud"  # noqa
        )

    new_user = User(
        username=create_user_request.username,
        password=bcrypt_context.hash(create_user_request.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"xabar": "Foydalanuvchi muvaffaqiyatli yaratildi", "foydalanuvchi_id": new_user.id}  # noqa


@auth_router.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: DBSessionDep
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login yoki parol noto‘g‘ri"
        )

    token = create_access_token(
        username=user.username,
        user_id=user.id,
        expires_delta=timedelta(minutes=20)
    )
    return {"access_token": token, "token_type": "Bearer"}


app.include_router(auth_router)
