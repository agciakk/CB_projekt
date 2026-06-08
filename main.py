from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI()

# Ścieżki
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ZEROFOUR_DIR = os.path.join(TEMPLATES_DIR, "zerofour")

# Podłączamy folder zerofour jako statyczny (CSS, JS, obrazy)
app.mount("/assets", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "assets")), name="assets")
app.mount("/images", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "images")), name="images")

# Szablony
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "zerofour/index.html", {"request": request})

@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(request, "zerofour/left-sidebar.html", {"request": request})

@app.get("/admin")
def admin(request: Request):
    return templates.TemplateResponse(request, "zerofour/no-sidebar.html", {"request": request})