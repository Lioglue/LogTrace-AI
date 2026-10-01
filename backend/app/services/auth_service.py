from sqlalchemy.orm import Session
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from app.config.settings import settings
from app.models.user import User
from app.schemas.user import UserCreate


class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8"),
            )
        except ValueError:
            return False

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        except jwt.PyJWTError:
            return None

    @staticmethod
    def create_user(db: Session, user_data: UserCreate) -> User:
        existing = db.query(User).filter(
            (User.username == user_data.username) | (User.email == user_data.email)
        ).first()
        if existing:
            raise ValueError("Username or email already exists")

        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=AuthService.hash_password(user_data.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not AuthService.verify_password(password, user.password_hash):
            return None
        return user