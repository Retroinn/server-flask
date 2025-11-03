from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class Category(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    color: str
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CategoryCreate(BaseModel):
    name: str
    color: str

class Task(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: Optional[str] = None
    status: str = "todo"  # todo, in_progress, done
    priority: str = "medium"  # low, medium, high
    category_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    due_date: Optional[datetime] = None
    user_id: str
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "todo"
    priority: str = "medium"
    category_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    due_date: Optional[str] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    category_id: Optional[str] = None
    tags: Optional[List[str]] = None
    due_date: Optional[str] = None

class DashboardStats(BaseModel):
    total_tasks: int
    todo_tasks: int
    in_progress_tasks: int
    completed_tasks: int
    overdue_tasks: int
    high_priority_tasks: int

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return User(**user)

# Auth routes
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name
    )
    
    user_dict = user.model_dump()
    user_dict['password'] = hash_password(user_data.password)
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    # Create default categories
    default_categories = [
        {"name": "Work", "color": "#3b82f6"},
        {"name": "Personal", "color": "#8b5cf6"},
        {"name": "Shopping", "color": "#ec4899"},
        {"name": "Health", "color": "#10b981"},
    ]
    
    for cat in default_categories:
        category = Category(
            name=cat["name"],
            color=cat["color"],
            user_id=user.id
        )
        cat_dict = category.model_dump()
        cat_dict['created_at'] = cat_dict['created_at'].isoformat()
        await db.categories.insert_one(cat_dict)
    
    # Create token
    access_token = create_access_token(data={"sub": user.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user)

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user_dict = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    
    if not user_dict or not verify_password(user_data.password, user_dict.get('password', '')):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user = User(**{k: v for k, v in user_dict.items() if k != 'password'})
    
    # Create token
    access_token = create_access_token(data={"sub": user.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# Category routes
@api_router.get("/categories", response_model=List[Category])
async def get_categories(current_user: User = Depends(get_current_user)):
    categories = await db.categories.find({"user_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    for cat in categories:
        if isinstance(cat.get('created_at'), str):
            cat['created_at'] = datetime.fromisoformat(cat['created_at'])
    
    return categories

@api_router.post("/categories", response_model=Category)
async def create_category(category_data: CategoryCreate, current_user: User = Depends(get_current_user)):
    category = Category(
        name=category_data.name,
        color=category_data.color,
        user_id=current_user.id
    )
    
    cat_dict = category.model_dump()
    cat_dict['created_at'] = cat_dict['created_at'].isoformat()
    
    await db.categories.insert_one(cat_dict)
    
    return category

@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, current_user: User = Depends(get_current_user)):
    result = await db.categories.delete_one({"id": category_id, "user_id": current_user.id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    
    return {"message": "Category deleted successfully"}

# Task routes
@api_router.get("/tasks", response_model=List[Task])
async def get_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    category_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = {"user_id": current_user.id}
    
    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    if category_id:
        query["category_id"] = category_id
    
    tasks = await db.tasks.find(query, {"_id": 0}).to_list(1000)
    
    # Convert ISO strings back to datetime objects
    for task in tasks:
        if isinstance(task.get('created_at'), str):
            task['created_at'] = datetime.fromisoformat(task['created_at'])
        if isinstance(task.get('updated_at'), str):
            task['updated_at'] = datetime.fromisoformat(task['updated_at'])
        if isinstance(task.get('due_date'), str):
            task['due_date'] = datetime.fromisoformat(task['due_date'])
        if isinstance(task.get('completed_at'), str):
            task['completed_at'] = datetime.fromisoformat(task['completed_at'])
    
    return tasks

@api_router.get("/tasks/stats", response_model=DashboardStats)
async def get_task_stats(current_user: User = Depends(get_current_user)):
    all_tasks = await db.tasks.find({"user_id": current_user.id}, {"_id": 0}).to_list(1000)
    
    total_tasks = len(all_tasks)
    todo_tasks = sum(1 for t in all_tasks if t.get('status') == 'todo')
    in_progress_tasks = sum(1 for t in all_tasks if t.get('status') == 'in_progress')
    completed_tasks = sum(1 for t in all_tasks if t.get('status') == 'done')
    high_priority_tasks = sum(1 for t in all_tasks if t.get('priority') == 'high' and t.get('status') != 'done')
    
    # Calculate overdue tasks
    now = datetime.now(timezone.utc)
    overdue_tasks = 0
    for task in all_tasks:
        if task.get('status') != 'done' and task.get('due_date'):
            due_date = task['due_date']
            if isinstance(due_date, str):
                due_date = datetime.fromisoformat(due_date)
            # Ensure due_date is timezone-aware
            if due_date.tzinfo is None:
                due_date = due_date.replace(tzinfo=timezone.utc)
            if due_date < now:
                overdue_tasks += 1
    
    return DashboardStats(
        total_tasks=total_tasks,
        todo_tasks=todo_tasks,
        in_progress_tasks=in_progress_tasks,
        completed_tasks=completed_tasks,
        overdue_tasks=overdue_tasks,
        high_priority_tasks=high_priority_tasks
    )

@api_router.post("/tasks", response_model=Task)
async def create_task(task_data: TaskCreate, current_user: User = Depends(get_current_user)):
    task = Task(
        title=task_data.title,
        description=task_data.description,
        status=task_data.status,
        priority=task_data.priority,
        category_id=task_data.category_id,
        tags=task_data.tags,
        user_id=current_user.id
    )
    
    if task_data.due_date:
        try:
            task.due_date = datetime.fromisoformat(task_data.due_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid due_date format")
    
    task_dict = task.model_dump()
    task_dict['created_at'] = task_dict['created_at'].isoformat()
    task_dict['updated_at'] = task_dict['updated_at'].isoformat()
    if task_dict.get('due_date'):
        task_dict['due_date'] = task_dict['due_date'].isoformat()
    if task_dict.get('completed_at'):
        task_dict['completed_at'] = task_dict['completed_at'].isoformat()
    
    await db.tasks.insert_one(task_dict)
    
    return task

@api_router.put("/tasks/{task_id}", response_model=Task)
async def update_task(
    task_id: str,
    task_data: TaskUpdate,
    current_user: User = Depends(get_current_user)
):
    # Get existing task
    existing_task = await db.tasks.find_one({"id": task_id, "user_id": current_user.id}, {"_id": 0})
    
    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Update fields
    update_data = task_data.model_dump(exclude_unset=True)
    
    if 'due_date' in update_data and update_data['due_date']:
        try:
            update_data['due_date'] = datetime.fromisoformat(update_data['due_date']).isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid due_date format")
    
    # Handle status change to done
    if update_data.get('status') == 'done' and existing_task.get('status') != 'done':
        update_data['completed_at'] = datetime.now(timezone.utc).isoformat()
    elif update_data.get('status') != 'done' and existing_task.get('status') == 'done':
        update_data['completed_at'] = None
    
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.tasks.update_one(
        {"id": task_id, "user_id": current_user.id},
        {"$set": update_data}
    )
    
    # Get updated task
    updated_task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    
    # Convert ISO strings back to datetime
    if isinstance(updated_task.get('created_at'), str):
        updated_task['created_at'] = datetime.fromisoformat(updated_task['created_at'])
    if isinstance(updated_task.get('updated_at'), str):
        updated_task['updated_at'] = datetime.fromisoformat(updated_task['updated_at'])
    if isinstance(updated_task.get('due_date'), str):
        updated_task['due_date'] = datetime.fromisoformat(updated_task['due_date'])
    if isinstance(updated_task.get('completed_at'), str):
        updated_task['completed_at'] = datetime.fromisoformat(updated_task['completed_at'])
    
    return Task(**updated_task)

@api_router.delete("/tasks/{task_id}")
async def delete_task(task_id: str, current_user: User = Depends(get_current_user)):
    result = await db.tasks.delete_one({"id": task_id, "user_id": current_user.id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {"message": "Task deleted successfully"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()