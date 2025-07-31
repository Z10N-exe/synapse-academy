from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
import logging
import os
import string
import random
from uuid import uuid4

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(title="Synapse Academy API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
users = {}  # {email: {"email": str, "hashed_password": str, "full_name": str, "role": str}}
courses = {}  # {id: {"title": str, "category": str, ...}}
lessons = {}  # {id: {"course_id": str, "title": str, ...}}

# JWT settings
SECRET_KEY = "f8a4b7c9d2e5f1a3b6c8d0e2f4a7b9c1d3e5f7a9b0c2d4e6f8a0b1c3d5e7f9a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 3000

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class User(BaseModel):
    email: str
    full_name: Optional[str] = None
    role: str = "student"

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Course(BaseModel):
    id: str
    title: str
    category: str
    description: str
    price: float
    instructor_id: str
    access_code: str
    cover_image: Optional[str] = None
    enrolled_students: List[str] = []

class Lesson(BaseModel):
    id: str
    course_id: str
    title: str
    content: str
    video_path: Optional[str] = None
    instructor_id: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"JWT encoding failed: {e}")
        raise HTTPException(status_code=500, detail="Token creation failed")

def generate_access_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        raise credentials_exception
    user = users.get(email)
    if user is None:
        raise credentials_exception
    return User(**user)

# Routes
@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to Synapse Academy API"}

@app.post("/signup/", tags=["Auth"])
async def signup(
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form("student")
):
    if email in users:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    user = {
        "email": email,
        "hashed_password": hashed_password,
        "full_name": full_name,
        "role": role if role in ["student", "instructor"] else "student"
    }
    users[email] = user
    logger.info(f"User created: {email}")
    return {"message": "User created successfully"}

@app.post("/token", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        logger.warning(f"Login failed for {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["email"]})
    logger.info(f"Login successful: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/user", response_model=User, tags=["User"])
async def get_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/courses/", response_model=Course, tags=["Courses"])
async def create_course(
    title: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    cover_image: UploadFile = File(None),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Not authorized")
    image_path = None
    if cover_image:
        image_path = f"uploads/{cover_image.filename}"
        try:
            with open(image_path, "wb") as f:
                f.write(await cover_image.read())
        except Exception as e:
            logger.error(f"Image upload failed: {e}")
            raise HTTPException(status_code=500, detail="Image upload failed")
    access_code = generate_access_code()
    while any(c["access_code"] == access_code for c in courses.values()):
        access_code = generate_access_code()
    course_id = str(uuid4())
    course = {
        "id": course_id,
        "title": title,
        "category": category,
        "description": description,
        "price": price,
        "instructor_id": current_user.email,
        "access_code": access_code,
        "cover_image": image_path,
        "enrolled_students": []
    }
    courses[course_id] = course
    logger.info(f"Course created: {title}")
    return Course(**course)

@app.post("/lessons/", tags=["Lessons"])
async def create_lesson(
    course_id: str = Form(...),
    title: str = Form(...),
    content: str = Form(...),
    video: UploadFile = File(None),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Not authorized")
    if course_id not in courses:
        raise HTTPException(status_code=404, detail="Course not found")
    video_path = None
    if video:
        video_path = f"uploads/{video.filename}"
        try:
            with open(video_path, "wb") as f:
                f.write(await video.read())
        except Exception as e:
            logger.error(f"Video upload failed: {e}")
            raise HTTPException(status_code=500, detail="Video upload failed")
    lesson_id = str(uuid4())
    lesson = {
        "id": lesson_id,
        "course_id": course_id,
        "title": title,
        "content": content,
        "video_path": video_path,
        "instructor_id": current_user.email
    }
    lessons[lesson_id] = lesson
    logger.info(f"Lesson created: {title}")
    return {"message": "Lesson created successfully"}

@app.get("/api/classes/", tags=["Courses"])
async def get_instructor_classes(current_user: User = Depends(get_current_user)):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Not authorized")
    instructor_courses = [c for c in courses.values() if c["instructor_id"] == current_user.email]
    logger.info(f"Fetched {len(instructor_courses)} classes for instructor")
    return instructor_courses

@app.get("/api/lessons/", tags=["Lessons"])
async def get_lessons(current_user: User = Depends(get_current_user)):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Not authorized")
    instructor_lessons = [l for l in lessons.values() if l["instructor_id"] == current_user.email]
    logger.info(f"Fetched {len(instructor_lessons)} lessons for instructor")
    return instructor_lessons

@app.get("/api/logs/", tags=["Logs"])
async def get_logs(current_user: User = Depends(get_current_user)):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Not authorized to view logs")
    
    try:
        # Read the log file
        log_file_path = "app.log"
        if not os.path.exists(log_file_path):
            raise HTTPException(status_code=404, detail="Log file not found")
        
        with open(log_file_path, "r") as log_file:
            logs = log_file.readlines()
        
        # Return last 100 lines of logs
        return {
            "message": "Logs retrieved successfully",
            "logs": logs[-100:],
            "total_lines": len(logs)
        }
    except Exception as e:
        logger.error(f"Failed to retrieve logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve logs")

if __name__ == "__main__":
    import uvicorn
    os.makedirs("uploads", exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=8000)