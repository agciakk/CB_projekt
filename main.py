from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os

# --- Importy dla Bazy Danych ---
from sqlalchemy.orm import Session
from database import engine, Base, get_db
import models

# --- Importy dla Szyfrowania Haseł ---
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

Base.metadata.create_all(bind=engine)

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ZEROFOUR_DIR = os.path.join(TEMPLATES_DIR, "zerofour")

app.mount("/assets", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "assets")), name="assets")
app.mount("/images", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "images")), name="images")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# ==========================================
# ENDPOINTY
# ==========================================

@app.get("/")
def home(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    # Pobieramy wszystkie zadania z bazy
    all_challenges = db.query(models.Challenge).all()
    
    # Przekazujemy je do szablonu HTML pod zmienną "challenges"
    return templates.TemplateResponse(
        request, 
        "zerofour/index.html", 
        {
            "request": request, 
            "username": logged_in_user,
            "challenges": all_challenges
        }
    )
@app.get("/register")
def show_register_form(request: Request, logged_in_user: str = Cookie(None)):
    return templates.TemplateResponse(request, "zerofour/register.html", {"request": request, "username": logged_in_user})

@app.post("/register")
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Nazwa użytkownika jest już zajęta!")

    new_user = models.User(username=username, password_hash=get_password_hash(password))
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@app.get("/login")
def show_login_form(request: Request, logged_in_user: str = Cookie(None)):
    return templates.TemplateResponse(request, "zerofour/login.html", {"request": request, "username": logged_in_user})

@app.post("/login")
def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Nieprawidłowy login lub hasło!")

    # Przekierowuje na stronę główną zamiast do "/dashboard"
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="logged_in_user", value=user.username)
    return response

@app.get("/logout")
def logout():
    # Usuwa ciasteczko i wraca na stronę główną
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("logged_in_user")
    return response
@app.get("/admin")
def show_admin_panel(request: Request, logged_in_user: str = Cookie(None)):
    # BEZPIECZEŃSTWO: Jeśli użytkownik nie jest zalogowany LUB jego nick to nie "admin"
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak dostępu! Tylko dla administratora.")

    # Jeśli to admin, wpuszczamy go do panelu
    return templates.TemplateResponse(
        request, 
        "zerofour/no-sidebar.html",  # Używamy szablonu bez pasków bocznych
        {"request": request, "username": logged_in_user}
    )

@app.post("/admin/add-challenge")
def add_challenge(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    points: int = Form(...),
    flag: str = Form(...),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    # Ponowna weryfikacja bezpieczeństwa przy wysyłaniu danych
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnień!")

    # Tworzymy nowy obiekt zadania na podstawie danych z formularza
    new_challenge = models.Challenge(
        title=title,
        description=description,
        category=category,
        points=points,
        flag=flag
    )

    # Zapisujemy w bazie danych
    db.add(new_challenge)
    db.commit()

    # Po udanym dodaniu odświeżamy stronę admina (lub możemy przekierować na główną)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
@app.get("/scoreboard")
def show_scoreboard(request: Request, logged_in_user: str = Cookie(None)):
    # Pokazuje tabelę wyników
    return templates.TemplateResponse(request, "zerofour/scoreboard.html", {"request": request, "username": logged_in_user})

@app.get("/rules")
def show_rules(request: Request, logged_in_user: str = Cookie(None)):
    # Pokazuje zasady gry
    return templates.TemplateResponse(request, "zerofour/rules.html", {"request": request, "username": logged_in_user})