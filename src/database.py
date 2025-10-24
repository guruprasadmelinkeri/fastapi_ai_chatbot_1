from fastapi import FastAPI, Depends, HTTPException,Header,APIRouter,Request
from sqlalchemy import create_engine, Column, Integer, String,Boolean,JSON,ForeignKey,DateTime,func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session,relationship
from pydantic import BaseModel
from auth.auth import hash, verify
from typing import List
from auth.access_token import create_access_token,create_refresh_token,ACCESS_TOKEN_EXPIRE_MINUTES,SECRET_KEY,ALGORITHM
from datetime import timedelta,datetime
import uuid
from fastapi.security import OAuth2PasswordBearer,APIKeyHeader
from jose import JWTError,jwt
import json
from auth.roles import require_role_session

import os
from dotenv import load_dotenv

app=FastAPI()
load_dotenv()
ADMIN_KEY=os.getenv("ADMIN_KEY")

# Initialize app
app = APIRouter()




DATABASE_URL = "sqlite:///user.db"
# Database setup
engine = create_engine("sqlite:///user.db", echo=True)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    unique_id = Column(String)
    hashed_password = Column(String, nullable=True)
    current_token = Column(String, nullable=True)
    ispremium=Column(Boolean, default=False)
    throttle=Column(JSON,default=[])
    tokens = relationship("RefreshToken", back_populates="user")
    role=Column(String,default="user")
    
class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False,index=True)
    promptid = Column(String, unique=True,  nullable=False)
    prompt = Column(String, nullable=False)
    answer = Column(String, nullable=False)
    

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    refresh_token = Column(String, nullable=False)
    access_token= Column(String, nullable=True)
    device_info = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    isrevoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="tokens")

@staticmethod
def generate_promptid(user_id: int, user_name: str):
    """Generate unique prompt ID using user ID, name, and current timestamp"""
    return f"{user_id}_{user_name}"

# Pydantic Schemas
class CreateUser(BaseModel):
    name: str
    email: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    class Config:
        orm_mode = True
    unique_id:str  # enables automatic conversion from SQLAlchemy objects

# Helper

def unique_id(user_id: str):
    return f"{user_id}_{int(datetime.utcnow().timestamp())}_{uuid.uuid4().hex[:6]}"
# Create tables
Base.metadata.create_all(bind=engine)

# Database Session
SessionLocal = sessionmaker(bind=engine)

def get_db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

# Routes


#route to create a user 
@app.put("/register", response_model=UserResponse)
def add_user(request:Request,user: CreateUser,password:str, db: Session = Depends(get_db_session)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    


    hashed_pw = hash(password)     
    db_user = User(
        name=user.name,
        email=user.email,
        unique_id=unique_id(user.name),
        hashed_password=hashed_pw
        
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def add_user_no_password(user: CreateUser):
    with SessionLocal() as db:
        if db.query(User).filter(User.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already exists")
        
        db_user = User(
            name=user.name,
            email=user.email,
            unique_id=unique_id(user.name),
            hashed_password=None  # No password for OAuth users
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        








# login route and creating access token
@app.post("/login")
def login(request: Request,email:str,password=str,db:Session=Depends(get_db_session)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify(password,user.hashed_password):
        raise HTTPException(status_code=404, detail="User not found")
    access_token=create_access_token({"sub":email},timedelta(minutes=1))
    refresh_token=create_access_token({"sub":email},timedelta(days=1))
    user.current_token=access_token
    db.add(user)
    db.commit()
    tokens = RefreshToken(
        user_id=user.id,
        refresh_token=refresh_token,
        access_token=access_token,
        device_info="unknown",
        expires_at=datetime.utcnow() + timedelta(days=7)    
        
    )


    request.session["email"] = email
    db.add(tokens)
    db.commit()
    db.refresh(tokens)





    return {"access_token":access_token,"refresh_token":refresh_token,"token_type":"bearer"}


@app.post("/logout")
def logout(request:Request, db: Session = Depends(get_db_session)):
    """
    Logout a user using email + password.
    Revokes all refresh tokens and clears the access token.
    """
    # Step 1: Verify credentials
    email=request.session.get("email")
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Step 2: Revoke all refresh tokens
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.isrevoked == False
    ).update({"isrevoked": True})

    # Step 3: Clear current access token
    user.current_token = None
    db.add(user)
    db.commit()
    request.session.clear()

    return {"message": "User successfully logged out"}
#  
@app.post("/refresh")
def refresh_access_token(request:Request,email: str, db: Session = Depends(get_db_session)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")


    refresh_token = get_latest_refresh_token(user.id)
    # Validate token
    token_entry = db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.refresh_token == refresh_token,
        RefreshToken.isrevoked == False,
        RefreshToken.expires_at > datetime.utcnow()
    ).first()

    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Revoke old token
    token_entry.isrevoked = True

    # Issue new tokens
    new_access = create_access_token({"sub": email}, )
    new_refresh = create_refresh_token({"sub": email}, )

    new_entry = RefreshToken(
        user_id=user.id,
        access_token=new_access,
        refresh_token=new_refresh,
        device_info="unknown",
        expires_at=datetime.utcnow() + timedelta(days=1)
    )
    db.add(new_entry)
    db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "access_token_expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }






##method to protect routes via acess tokens


def get_current_user(request:Request,token:str):
    credential_error = HTTPException(
        status_code=401, detail="couldn't verify credentials"
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise credential_error
    except JWTError:
        raise credential_error
    except jwt.ExpiredSignatureError:
        # Access token expired → call refresh route internally
        user=get_user_by_email(email)
        refresh_token=get_latest_refresh_token(user.id)
        with SessionLocal() as db:
            user = db.query(User).filter(User.current_token == token).first()
            if not user or not refresh_token:
                raise HTTPException(status_code=401, detail="Session expired, login again")

            # Call your refresh function directly
            new_tokens = refresh_access_token(Request,
                email=user.email,
                db=db
            )

            # Update user's current token
            user.current_token = new_tokens["access_token"]
            db.add(user)
            db.commit()

            # Return user object
            return fetch_user(user.email)

    user = fetch_user(email)
    if not user:
        raise credential_error

    return user

def get_current_user_new(request:Request,token: str):
    credential_error = HTTPException(status_code=401, detail="Couldn't verify credentials")

    try:
        # Try decoding access token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise credential_error

        # Normal token valid
        user = fetch_user(email)
        if not user:
            raise credential_error

        return user

    except jwt.ExpiredSignatureError:
        # Access token expired → use refresh token
        with SessionLocal() as db:
            # Fetch user by current token
            user = db.query(User).filter(User.current_token == token).first()
            if not user:
                raise HTTPException(status_code=401, detail="Session expired, login again")

            # Get latest valid refresh token
            refresh_token = get_latest_refresh_token(user.id)
            if not refresh_token:
                raise HTTPException(status_code=401, detail="No valid refresh token, login again")

            # Call existing refresh route
            new_tokens = refresh_access_token(Request,email=user.email, db=db)

            # Update user's current access token
            user.current_token = new_tokens["access_token"]
            db.add(user)
            db.commit()

            # Return user object
            return fetch_user(user.email)

    except jwt.PyJWTError:
        # Any other JWT errors
        raise credential_error


def verify_user_by_email(email: str):
    """
    Fully self-contained: handles DB session internally,
    fetches the user, checks for stored JWT, verifies it,
    and returns the verified user object.
    """
    with SessionLocal() as db:  # internal DB session
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.current_token:
            raise HTTPException(status_code=401, detail="No active session")
        # Verify JWT internally
        return get_current_user_new(Request,user.current_token)

@app.put("/premium")
def set_premium(request:Request,email:str):
    with SessionLocal() as db:
        user=db.query(User).filter(User.email==email).first()
        if not user:
            raise  HTTPException(status_code=401, detail="User not found")
        user.ispremium=True
        db.add(user)
        db.commit()
        db.refresh(user)

@app.get("/premium/staus")
def get_premium(request:Request,email:str):
    with SessionLocal() as db:
        user=db.query(User).filter(User.email==email).first()
        if not user:
            raise  HTTPException(status_code=401, detail="User not found")
        return user.ispremium






@app.get("/user", response_model=UserResponse)
def get_user_by_email(request:Request,email: str, db: Session = Depends(get_db_session)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



@app.get("/users/display",response_model=List[UserResponse])
def displayall(request:Request,db:Session=Depends(get_db_session)):
    email = request.session.get("email")
    admin = verify_user_by_email(email)
    require_role_session(admin, "admin")

    users=db.query(User).all()
    if not users:
        raise HTTPException(status_code=404,detail="no users to display")
    return users        










# funtions to use in outer modules

def fetch_user(email:str,db: Session=None):
    if db is None:
        with SessionLocal() as db:

    
            user = db.query(User).filter(User.email == email).first()
            if not user:
                return None
            else:
                return user
    else:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        else:
            return user

def store_history(user:User,prompt:str,answer:str,db:Session=None):
    if db is None:
        with SessionLocal() as db:
            new_history=History(
                user_id=user.id,
                promptid=unique_id(user.id),
                prompt=prompt,
                answer=answer
            )
            db.add(new_history)
            db.commit()
            db.refresh(new_history)
            return
    else:

        new_history=History(
            user_id=user.id,
            promptid=unique_id(user.id),
            prompt=prompt,
            answer=answer
        )
        db.add(new_history)
        db.commit()
        db.refresh(new_history)

def store_to_db(user:User,prompt:str,answer:str):
    store_history(user,prompt,answer)





def get_user_chats(email: str, db: Session = None):
    if db is None:
        with SessionLocal() as db:    
            user = db.query(User).filter(User.email == email).first()
            if not user:
                return None
            
            chats = db.query(History).filter(History.user_id == user.id).all()
            if not chats:
                return None
            return chats
    else:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        
        chats = db.query(History).filter(History.user_id == user.id).all()
        if not chats:
            
            return None
        return chats
        


def chat_db(email:str):
    return get_user_chats(email)



#function to store current  
def get_throttle(email:str):
    with SessionLocal() as db:
        user=db.query(User).filter(User.email==email).first()
        if not user:
            raise  HTTPException(status_code=401, detail="User not found")
        return json_to_list(user.throttle)

def update_throttle(throtle:list,email:str):
    with SessionLocal() as db:
        user=db.query(User).filter(User.email==email).first()
        if not user:
            raise  HTTPException(status_code=401, detail="User not found")
        user.throttle=list_to_json(throtle)
        db.add(user)
        db.commit()
        db.refresh(user)

    

import json

def json_to_list(json_data):
    """Convert JSON string to Python list."""
    if not json_data:
        return []
    try:
        return json.loads(json_data)
    except (TypeError, json.JSONDecodeError):
        return []

def list_to_json(py_list):
    """Convert Python list to JSON string."""
    if py_list is None:
        return "[]"
    try:
        return json.dumps(py_list)
    except (TypeError, ValueError):
        return "[]"


def get_latest_refresh_token(user_id: int):
    """
    Returns the latest valid refresh token for the given user.
    If none exists or all are isrevoked/expired, returns None.
    """

    with SessionLocal() as db:
        token_entry = db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.isrevoked == False,
            RefreshToken.expires_at > datetime.utcnow()
        ).order_by(RefreshToken.created_at.desc()).first()

        if token_entry:
            return token_entry.refresh_token
        return None
    





def create_admin(email: str, name: str, password: str):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == email).first():
            print("User already exists")
            return
        admin_user = User(
            email=email,
            name=name,
            hashed_password=hash(password),
            unique_id=unique_id(name),
            role="admin"
        )
        db.add(admin_user)
        db.commit()
        print(f"Admin {email} created successfully.")
    finally:
        db.close()


create_admin(email="admin3@chatbot.com", name="ADMIN_", password=ADMIN_KEY)


