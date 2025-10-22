from fastapi import Depends, HTTPException, status
  # your existing helper

def require_role_session(user, *allowed_roles):
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied")
    

