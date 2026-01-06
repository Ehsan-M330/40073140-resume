from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from datetime import datetime
from enum import Enum
from typing import List, Optional
import jwt
import os
from passlib.context import CryptContext

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./resume.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# FastAPI app
app = FastAPI(title="Resume Backend API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Models
class RequestStatus(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"

class ProjectRequest(Base):
    __tablename__ = "project_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    phone = Column(String(20))
    project_description = Column(Text, nullable=False)
    project_type = Column(String(50))
    budget_range = Column(String(50))
    timeline = Column(String(50))
    status = Column(SQLEnum(RequestStatus), default=RequestStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class ProjectRequestCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    project_description: str
    project_type: Optional[str] = None
    budget_range: Optional[str] = None
    timeline: Optional[str] = None

class ProjectRequestResponse(BaseModel):
    id: int
    name: str
    email: str
    phone: Optional[str]
    project_description: str
    project_type: Optional[str]
    budget_range: Optional[str]
    timeline: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class ProjectRequestUpdate(BaseModel):
    status: Optional[RequestStatus] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        await self.broadcast_count()
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast_count(self):
        count = len(self.active_connections)
        message = {"count": count}
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# Routes
@app.get("/")
async def root():
    return {"message": "Resume Backend API"}

@app.get("/api/test-login")
async def test_login():
    """Test endpoint to check admin credentials (remove in production)"""
    return {
        "admin_username": ADMIN_USERNAME,
        "admin_password_set": bool(ADMIN_PASSWORD),
        "message": "Use username: admin, password: admin123"
    }

@app.post("/api/project-request", response_model=ProjectRequestResponse)
async def create_project_request(request: ProjectRequestCreate, db: Session = Depends(get_db)):
    db_request = ProjectRequest(**request.dict())
    db.add(db_request)
    db.commit()
    db.refresh(db_request)
    return db_request

@app.get("/api/project-requests", response_model=List[ProjectRequestResponse])
async def get_project_requests(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    username: str = Depends(verify_token)
):
    requests = db.query(ProjectRequest).offset(skip).limit(limit).all()
    return requests

@app.get("/api/project-requests/{request_id}", response_model=ProjectRequestResponse)
async def get_project_request(
    request_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(verify_token)
):
    request = db.query(ProjectRequest).filter(ProjectRequest.id == request_id).first()
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    return request

@app.put("/api/project-requests/{request_id}", response_model=ProjectRequestResponse)
async def update_project_request(
    request_id: int,
    request_update: ProjectRequestUpdate,
    db: Session = Depends(get_db),
    username: str = Depends(verify_token)
):
    db_request = db.query(ProjectRequest).filter(ProjectRequest.id == request_id).first()
    if not db_request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if request_update.status:
        db_request.status = request_update.status
    
    db.commit()
    db.refresh(db_request)
    return db_request

@app.delete("/api/project-requests/{request_id}")
async def delete_project_request(
    request_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(verify_token)
):
    db_request = db.query(ProjectRequest).filter(ProjectRequest.id == request_id).first()
    if not db_request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    db.delete(db_request)
    db.commit()
    return {"message": "Request deleted successfully"}

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(login_request: LoginRequest):
    # Debug: Print received credentials (remove in production)
    print(f"Login attempt - Username: {login_request.username}, Password: {login_request.password}")
    print(f"Expected - Username: {ADMIN_USERNAME}, Password: {ADMIN_PASSWORD}")
    
    # Trim whitespace from inputs
    username = login_request.username.strip()
    password = login_request.password.strip()
    
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    token = jwt.encode({"sub": username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.websocket("/ws/online-users")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast_count()

@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    import os
    admin_path = os.path.join(os.path.dirname(__file__), "admin.html")
    with open(admin_path, "r", encoding="utf-8") as f:
        return f.read()

