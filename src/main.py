import os 
from dotenv import load_dotenv
from fastapi import FastAPI,Depends,HTTPException
from pydantic import BaseModel
from models.nvidia_client import Nvidia
from database import User,fetch_user,store_to_db,chat_db,get_current_user,verify_user_by_email
from usage_limit import rate_limit
from fastapi.middleware.cors import CORSMiddleware
from auth.googleauth import router as google_router

from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
app=FastAPI()
load_dotenv()

app.add_middleware(SessionMiddleware, secret_key="supersecret")  # must be before router

app.include_router(google_router, prefix="/google", tags=["google"])



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
async def chat(request:ChatRequest,email:str):
    
    new_user=verify_user_by_email(email)
    if not new_user:
        
        raise HTTPException(status_code=404,detail="user not found")
    else:
        rate_limit(new_user.email)
        response_text=ai_model.chat(request.prompt)
        response=ChatResponse(response=response_text)

        store_to_db(new_user,request.prompt,response.response)
        
        return response

@app.get("/chat/history")
async def history(email:str):
    chats=chat_db(email)
    if not chats:
        raise HTTPException(status_code=404,detail="no chats found")
    return chats



