from fastapi import Request
from fastapi.security import OAuth2
from typing import Optional

class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(self, tokenUrl: str, scheme_name: Optional[str] = None, auto_error: bool = True):
        flows = {
            "password": {
                "tokenUrl": tokenUrl,
                "scopes": {}
            }
        }
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        # Try to get the token from the Authorization header first
        authorization: str = request.headers.get("Authorization")
        if authorization:
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() == "bearer":
                return token

        # Fallback: read from cookie
        token = request.cookies.get("access_token")
        if token:
            return token

        if self.auto_error:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            return None
