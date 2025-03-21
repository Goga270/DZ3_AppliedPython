from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import redis
import random
import string
import datetime
from passlib.context import CryptContext
import logging
import qrcode
from io import BytesIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


DATABASE_URL = "postgresql://user:password@db/shortener"
REDIS_URL = "redis://redis:6379/0"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    links = relationship("Link", back_populates="owner")


class Link(Base):
    __tablename__ = "links"
    id = Column(Integer, primary_key=True, index=True)
    original_url = Column(String, nullable=False)
    short_code = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    visit_count = Column(Integer, default=0)
    max_visits = Column(Integer, nullable=True)
    is_disabled = Column(Integer, default=0)  # 0 - активна, 1 - отключена
    last_used = Column(DateTime, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="links")


Base.metadata.create_all(bind=engine)

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_short_code(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class ShortenRequest(BaseModel):
    original_url: HttpUrl
    custom_alias: str | None = None
    expires_at: datetime.datetime | None = None
    max_visits: int | None = None
    is_disabled: int = 0  # По умолчанию 0 (активна)


@app.post("/register")
def register(username: str, password: str, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = get_password_hash(password)
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()

    return {"message": "User registered successfully"}


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return {"access_token": user.username, "token_type": "bearer"}


@app.post("/links/shorten")
def shorten_link(request: ShortenRequest, db: Session = Depends(get_db), token: str = Security(oauth2_scheme)):
    user = db.query(User).filter(User.username == token).first()

    if request.custom_alias:
        if db.query(Link).filter_by(short_code=request.custom_alias).first():
            raise HTTPException(status_code=400, detail="Alias already taken")
        short_code = request.custom_alias
    else:
        short_code = generate_short_code()
        while db.query(Link).filter_by(short_code=short_code).first():
            short_code = generate_short_code()

    normalized_url = str(request.original_url).rstrip("/")

    link = Link(original_url=normalized_url, short_code=short_code, expires_at=request.expires_at,
                max_visits=request.max_visits, is_disabled=request.is_disabled, owner=user)
    db.add(link)
    db.commit()
    redis_client.setex(short_code, 3600, str(request.original_url))
    return {"short_url": f"http://localhost:8000/{short_code}", "short_code": short_code}


@app.get("/links/{short_code}")
def redirect_link(short_code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link or (link.expires_at and link.expires_at < datetime.datetime.utcnow()):
        raise HTTPException(status_code=404, detail="Link not found or expired")

    if link.is_disabled:
        raise HTTPException(status_code=403, detail="Link is currently disabled")

    link.visit_count += 1
    link.last_used = datetime.datetime.utcnow()

    if link.max_visits and link.visit_count >= link.max_visits:
        db.delete(link)
        db.commit()
        redis_client.delete(short_code)
        raise HTTPException(status_code=410, detail="Link expired due to max visits")

    db.commit()
    return {"original_url": link.original_url}


@app.delete("/links/{short_code}")
def delete_link(short_code: str, db: Session = Depends(get_db), token: str = Security(oauth2_scheme)):
    user = db.query(User).filter(User.username == token).first()
    link = db.query(Link).filter_by(short_code=short_code, owner=user).first()
    if not link:
        raise HTTPException(status_code=403, detail="Not authorized or link not found")
    db.delete(link)
    db.commit()
    redis_client.delete(short_code)
    return {"message": "Link deleted"}


@app.put("/links/{short_code}")
def update_link(short_code: str, new_url: HttpUrl, db: Session = Depends(get_db), token: str = Security(oauth2_scheme)):
    user = db.query(User).filter(User.username == token).first()
    link = db.query(Link).filter_by(short_code=short_code, owner=user).first()
    if not link:
        raise HTTPException(status_code=403, detail="Not authorized or link not found")
    link.original_url = str(new_url)
    db.commit()
    redis_client.setex(short_code, 3600, str(new_url))
    return {"message": "Link updated"}


@app.get("/links/{short_code}/stats")
def link_stats(short_code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    return {
        "original_url": link.original_url,
        "created_at": link.created_at,
        "visit_count": link.visit_count,
        "last_used": link.last_used
    }


@app.post("/links/search")
def search_link(request: ShortenRequest, db: Session = Depends(get_db)):
    normalized_url = str(request.original_url).rstrip("/")
    link = db.query(Link).filter_by(original_url=normalized_url).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"short_code": link.short_code}

@app.get("/links/{short_code}/qr")
def get_qr_code(short_code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    qr = qrcode.make(f"http://localhost/{short_code}")
    img_io = BytesIO()
    qr.save(img_io, format="PNG")
    img_io.seek(0)

    return StreamingResponse(img_io, media_type="image/png")


@app.put("/links/{short_code}/toggle")
def toggle_link(short_code: str, db: Session = Depends(get_db), token: str = Security(oauth2_scheme)):
    user = db.query(User).filter(User.username == token).first()
    link = db.query(Link).filter_by(short_code=short_code, owner=user).first()

    if not link:
        raise HTTPException(status_code=403, detail="Not authorized or link not found")

    link.is_disabled = 1 if link.is_disabled == 0 else 0
    db.commit()

    status = "disabled" if link.is_disabled else "enabled"
    return {"message": f"Link {short_code} is now {status}"}
