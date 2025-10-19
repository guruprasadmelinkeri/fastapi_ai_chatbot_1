from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional
from dotenv import load_dotenv
import os
load_dotenv(dotenv_path="/home/sadlin/Shared/backenddev/fast_api/.env") 
SECRET_KEY=os.getenv("SECRET_KEY")


SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set in environment variables")



ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

def create_access_token(data:dict,expires_delta:Optional[timedelta]=None):
    to_encode=data.copy()
    expire=datetime.utcnow()+(expires_delta if expires_delta else timedelta(minutes=1))
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data:dict,expires_delta:Optional[timedelta]=None):
    to_encode=data.copy()
    expire=datetime.utcnow()+(expires_delta if expires_delta else timedelta(days=7))
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

