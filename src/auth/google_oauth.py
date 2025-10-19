# auth/google_oauth.py

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuth
from starlette.responses import RedirectResponse
from dotenv import load_dotenv

import os

from database import get_db_session, User,RefreshToken
from datetime import datetime, timedelta
from auth.access_token import create_access_token,create_refresh_token

load_dotenv(dotenv_path="/home/sadlin/Shared/backenddev/fast_api/.env") 

router = APIRouter(prefix="/auth/google", tags=["Google Auth"])

# ⚡ OAuth setup
oauth = OAuth()
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    client_kwargs={"scope": "openid email profile"},
)

# ------------------------
# Step 1: Redirect to Google
# ------------------------
@router.get("/login")
async def google_login(request: Request):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    return await google.authorize_redirect(request, redirect_uri)

# ------------------------
# Step 2: Callback from Google
# ------------------------
@router.get("/callback")
async def google_callback(request: Request, db: Session = Depends(get_db_session)):
    try:
        token = await google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth token exchange failed: {e}")

    # Debug info (optional, remove in production)
    print("Token received:", token)

    try:
        # Fetch user info
        user_info = token.get("userinfo")
        if not user_info:
            user_info = await google.parse_id_token(request, token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch user info: {e}")

    if not user_info:
        raise HTTPException(status_code=400, detail="No user info received from Google")

    email = user_info.get("email")
    name = user_info.get("name")
    google_id = user_info.get("sub")

    # ------------------------
    # Step 3: Create or fetch user
    # ------------------------
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name=name,
            email=email,
            unique_id=google_id,
            hashed_password=None,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # ------------------------
    # Step 4: Issue JWT
    # ------------------------
    access_token = create_access_token({"sub": email})
    user.current_token = access_token
    refresh_token = create_refresh_token({"sub": email})
    new_entry = RefreshToken(
        user_id=user.id,
        access_token=access_token  ,
        refresh_token=refresh_token,
        device_info="unknown",
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(new_entry)
    
    db.commit()

    # ------------------------
    # Step 5: Return JSON (or redirect to frontend)
    # ------------------------
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"email": email, "name": name}
    }