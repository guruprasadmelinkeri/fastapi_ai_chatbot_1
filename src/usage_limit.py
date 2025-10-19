import time
from fastapi import HTTPException,status
from database import get_premium,get_throttle,update_throttle

PREMIUM_LIMIT=5
PREMIUM_TIME=6000

FREE_LIMIT=3
FREE_TIME=6000

def rate_limit(email:str):
    current_time=time.time()

    requests=get_throttle(email)

    if(get_premium(email)):
        Rate_Limit=PREMIUM_LIMIT
        Time_Limit=PREMIUM_TIME
    else:
        Rate_Limit=FREE_LIMIT
        Time_Limit=FREE_TIME
    

    requests= [
        t for t in requests if t > current_time - Time_Limit
    ]
    
    if len(requests)>=Rate_Limit:
        next_request=Time_Limit-(current_time-requests[0])
        
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,detail=f"You have exausted your chat qouta try after {next_request} seconds")
    else:
        current_usage=len(requests)+1
        print(f"{current_usage}/{Rate_Limit} chats used")
    requests.append(current_time)
    update_throttle(requests,email)
    
    return True