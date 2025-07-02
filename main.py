from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import os, shutil, uuid

from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

# --- Configuration ---
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# --- DB Setup ---
Base = declarative_base()
engine = create_engine("sqlite:///./securefiles.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# --- JWT ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)  # 'ops' or 'client'
    is_verified = Column(Boolean, default=False)

class FileRecord(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    path = Column(String)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class DownloadToken(Base):
    __tablename__ = "download_tokens"
    token = Column(String, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- Schemas ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# --- FastAPI App ---
app = FastAPI()

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(lambda: None), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
    try:
        payload = decode_token(token)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- Routes ---
@app.post("/ops/login", response_model=Token)
def login_ops(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email, User.role == "ops").first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/client/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw, role="client")
    db.add(new_user)
    db.commit()
    return {"encrypted_url": f"/client/verify-email?email={user.email}"}  # Simulated

@app.post("/client/verify-email")
def verify_email(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_verified = True
    db.commit()
    return {"message": "Email verified"}

@app.post("/client/login", response_model=Token)
def login_client(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email, User.role == "client").first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "ops":
        raise HTTPException(status_code=403, detail="Only Ops can upload files")
    if not file.filename.endswith((".docx", ".pptx", ".xlsx")):
        raise HTTPException(status_code=400, detail="Invalid file type")
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "_" + file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    record = FileRecord(filename=file.filename, path=file_path, uploader_id=user.id)
    db.add(record)
    db.commit()
    return {"message": "Upload successful"}

@app.get("/files")
def list_files(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "client":
        raise HTTPException(status_code=403, detail="Only clients can view files")
    return db.query(FileRecord).all()

@app.get("/download-link/{file_id}")
def get_download_link(file_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "client" or not user.is_verified:
        raise HTTPException(status_code=403, detail="Not authorized")
    token = str(uuid.uuid4())
    db_token = DownloadToken(token=token, file_id=file_id, user_id=user.id)
    db.add(db_token)
    db.commit()
    return {"download-link": f"/download/{token}", "message": "success"}

@app.get("/download/{token}")
def download_file(token: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_token = db.query(DownloadToken).filter(DownloadToken.token == token).first()
    if not db_token or db_token.user_id != user.id:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
    file_record = db.query(FileRecord).filter(FileRecord.id == db_token.file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_record.path, filename=file_record.filename)
