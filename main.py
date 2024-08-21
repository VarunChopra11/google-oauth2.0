import uvicorn
import webbrowser
import requests as req
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
# from fastapi.security import OAuth2AuthorizationCodeBearer
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from starlette.responses import RedirectResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware




load_dotenv()   # Load environment variables from a .env file
config = Config('.env')
app = FastAPI()

# Add session middleware for session management
app.add_middleware(SessionMiddleware, secret_key=config("SECRET_KEY"))

# Google OAuth2 configurations
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/callback"
GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = "openid email profile https://mail.google.com/"

@app.get("/login")
def login():
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google client ID is not configured.")
    
    google_login_url = (
        f"{GOOGLE_AUTHORIZATION_ENDPOINT}?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&scope={GOOGLE_SCOPES}"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return RedirectResponse(google_login_url)

@app.get("/auth/callback")
async def auth_callback(code: str):
    """
    Handles the OAuth2 callback by exchanging the authorization code for tokens and validating the ID token.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided.")
    
    token_uri = GOOGLE_TOKEN_ENDPOINT
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    try:
        response = req.post(token_uri, data=data)
        response.raise_for_status()  # Raise an exception for HTTP errors
    except req.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to exchange authorization code for tokens: {str(e)}")
    
    response_json = response.json()

    # Ensure the id_token is present in the response if not an exception is raised with status code 400.
    if "id_token" not in response_json:
        raise HTTPException(status_code=400, detail="Authentication failed: ID token not found.")

    # Validate the ID token and extract the user's information
    try:
        id_info = id_token.verify_oauth2_token(response_json["id_token"], google_requests.Request(), GOOGLE_CLIENT_ID, clock_skew_in_seconds=60)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {str(e)}")

    # Return the user's information along with tokens
    return {
        "email": id_info["email"],
        "name": id_info["name"],
        "picture": id_info["picture"],
        "access_token": response_json.get("access_token"),
        "id_token": response_json.get("id_token"),
        "refresh_token": response_json.get("refresh_token"),
        "expires_in": response_json.get("expires_in"),
        "token_type": response_json.get("token_type"),
        "scope": response_json.get("scope")
    }

# Call this function to run the server from the backend or you can also run it by running the main.py file if testing the auth model alone.
def run_server():
    webbrowser.open("http://localhost:8000/login")
    uvicorn.run(app, host="localhost", port=8000)

#Remove this if you are running the server from backend.
if __name__ == "__main__":
    run_server()