from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt

# Secret key for JWT encoding and decoding
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2
REFRESH_TOKEN_EXPIRE_DAYS = 4

app = FastAPI(
    title="Auth Challenge API",
    description="""
    This API provides authentication and refresh token mechanisms.

    ## Endpoints:
    - `/register`: Register a new user.
    - `/login`: Login with email & password to get access & refresh tokens.
    - `/refresh`: Refresh an expired access token using a refresh token.
    - `/protected`: Access a protected resource (requires an access token).

    **Your task:** Integrate this authentication system into another Python app.
    """,
    version="1.0.0"
)

# In-memory store for registered users (email: password)
fake_users_db = {}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta):
    """Generates a JWT access token with expiration time."""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# === Models for Documentation ===
class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshRequest(BaseModel):
    refresh_token: str

class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str

# === Endpoints ===
@app.post("/register", summary="Register a new user", status_code=201)
async def register(request: RegisterRequest):
    """
    Registers a new user with an **email** and **password**.

    - **email**: The user's email (must be unique).
    - **password**: The user's password.

    ### Responses:
    - `201 Created`: Successfully registered.
    - `400 Bad Request`: Email already exists or missing fields.
    """
    email = request.email
    password = request.password
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    if email in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    fake_users_db[email] = password
    return {"message": "User registered successfully"}

@app.post("/login", response_model=LoginResponse, summary="Login and receive access/refresh tokens")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticates a user and returns **access & refresh tokens**.

    - **username (email)**: The user's email.
    - **password**: The user's password.

    ### Responses:
    - `200 OK`: Returns access & refresh tokens.
    - `401 Unauthorized`: Invalid credentials.
    """
    user_password = fake_users_db.get(form_data.username)
    if not user_password or user_password != form_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token({"sub": form_data.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_access_token({"sub": form_data.username}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh", response_model=RefreshResponse, summary="Refresh an expired access token")
async def refresh_token(request: RefreshRequest):
    """
    Uses a **refresh token** to generate a new **access token**.

    - **refresh_token**: A valid refresh token.

    ### Responses:
    - `200 OK`: Returns a new access token.
    - `401 Unauthorized`: Invalid or expired refresh token.
    """
    refresh_token = request.refresh_token

    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        access_token = create_access_token({"sub": email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": access_token, "refresh_token": refresh_token}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/protected", summary="Access a protected resource")
async def protected_route(token: str = Depends(oauth2_scheme)):
    """
    Access a **protected route** that requires a valid **access token**.

    - **Authorization Header**: `"Bearer <access_token>"`

    ### Responses:
    - `200 OK`: Access granted.
    - `401 Unauthorized`: Invalid or expired token.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        return {"message": f"Access granted to {email}"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
