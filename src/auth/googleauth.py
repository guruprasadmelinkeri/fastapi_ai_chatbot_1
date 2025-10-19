from fastapi import APIRouter, Request, Depends, HTTPException
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import os

from auth.access_token import create_access_token,create_refresh_token
from database import get_db_session, User ,unique_id,RefreshToken # your session dependency
from datetime import datetime, timedelta

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

router = APIRouter()

# ---------------- OAuth Setup ---------------- #
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ---------------- Login Route ---------------- #
@router.get("/login")
async def login(request: Request):
    host = request.url.hostname
    redirect_uri = "http://127.0.0.1:8000/google/login/callback" if host == "127.0.0.1" else "http://localhost:8000/google/login/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

# ---------------- Callback Route ---------------- #
@router.get("/login/callback")
async def login_callback(request: Request, db: Session = Depends(get_db_session)):
    try:
        # Step 1: Exchange code for token
        token = await oauth.google.authorize_access_token(request)

        # Step 2: Get ID token
        id_token = token.get("id_token")
        if not id_token:
            raise HTTPException(status_code=400, detail="No id_token returned by Google. Ensure 'openid' scope is used.")

        # Step 3: Parse user info
        nonce = token.get("nonce")
        user_info = await oauth.google.parse_id_token(token=token, nonce=nonce)
        email = user_info.get("email")
        name = user_info.get("name") or "Unknown"

        if not email:
            raise HTTPException(status_code=400, detail="Google did not return an email.")

        # Step 4: Check if user exists
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                name=name,
                unique_id=unique_id(email)
            )
            db.add(user)
            db.commit()
            db.refresh(user)  # get user.id after insert

        # Step 5: Generate tokens
        access_token = create_access_token({"sub": email})
        refresh_token = create_refresh_token({"sub": email})

        # Step 6: Store refresh token in DB
        new_entry = RefreshToken(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            device_info="unknown",
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db.add(new_entry)

        # Step 7: Save access token to user
        user.current_token = access_token
        db.add(user)
        db.commit()

        # Step 8: Return user info + tokens
        return {
            "email": user.email,
            "name": user.name,
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Login callback failed: {str(e)}")
