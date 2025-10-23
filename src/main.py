import os 
from dotenv import load_dotenv
from fastapi import FastAPI,Depends,HTTPException,Request
from pydantic import BaseModel
from models.nvidia_client import Nvidia
from database import User,fetch_user,store_to_db,chat_db,verify_user_by_email
from usage_limit import rate_limit
from fastapi.middleware.cors import CORSMiddleware
from auth.googleauth import router as google_router

from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from database import app as database_app
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse



limiter=Limiter(key_func=get_remote_address)




app=FastAPI()
load_dotenv()


app.state.limiter = limiter
# Handle "RateLimitExceeded" globally
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    )


def user_or_ip_key(request: Request):
    """
    Use the logged-in user's email if available,
    otherwise fallback to IP address.
    """
    user_email = request.session.get("email")
    if user_email:
        return str(user_email)
    return get_remote_address(request)

limiter = Limiter(key_func=user_or_ip_key)





app.add_middleware(SessionMiddleware, secret_key="supersecret")  # must be before router

# Function to apply rate limiting to all routes in a router
def apply_rate_limit_to_router(router, limit: str):
    for route in router.routes:
        if hasattr(route, "endpoint"):  # make sure it's an actual endpoint
            route.endpoint = limiter.limit(limit)(route.endpoint)




apply_rate_limit_to_router(google_router, "5/minute")
apply_rate_limit_to_router(database_app, "5/minute")



app.include_router(google_router, prefix="/google", tags=["google"])
app.include_router(database_app)
app.include_router

class ChatResponse(BaseModel):
    response:str
class ChatRequest(BaseModel):
    prompt:str
## loading the system prompt
def load_system_prompt():

    with open("systemprompt.md","r") as f:
        return f.read()
system_prompt=load_system_prompt()
## getting the api key

nvidia_key=os.getenv("nvidia_key")

##creating the ai model object
ai_model=Nvidia(nvidia_key,system_prompt)

@app.get("/")
async def root():
    return "api is running "    
@app.post("/chat",)
@limiter.limit("10/minute") 
async def chat(payload:ChatRequest,request: Request ):
    email=request.session.get("email")
    new_user=verify_user_by_email(email)
    if not new_user:
        
        raise HTTPException(status_code=404,detail="user not found")
    else:
        rate_limit(new_user.email)
        response_text=ai_model.chat(payload.prompt)
        response=ChatResponse(response=response_text)

        store_to_db(new_user,payload.prompt,response.response)
        
        return response



@app.get("/chat/history")
@limiter.limit("10/minute") 
async def history(request: Request):
    email=request.session.get("email")
    chats=chat_db(email)
    if not chats:
        raise HTTPException(status_code=404,detail="no chats found")
    return chats



