import os 
from dotenv import load_dotenv
from fastapi import FastAPI,Depends
from pydantic import BaseModel
from models.nvidia_client import Nvidia
from fastapi.middleware.cors import CORSMiddleware

app=FastAPI()

# Allow your frontend origin (or * for all during development)
origins = [
    "http://localhost:5500",  # or where your HTML page is served
    "http://127.0.0.1:5500",
    "http://localhost:8000",  # optional
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # or ["*"] for development
    allow_credentials=True,
    allow_methods=["*"],    # allow POST, GET, OPTIONS, etc.
    allow_headers=["*"],
)




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
load_dotenv()
nvidia_key=os.getenv("nvidia_key")

##creating the ai model object
ai_model=Nvidia(nvidia_key,system_prompt)



@app.get("/")
async def root():
    return "api is running "
@app.post("/chat",response_model=ChatResponse)
async def chat(request:ChatRequest):
    response_text=ai_model.chat(request.prompt)
    return ChatResponse(response=response_text)