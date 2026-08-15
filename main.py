# -*- coding: utf-8 -*-
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
import os

from sqlalchemy.orm import Session
from database import engine, Base, get_db, SessionLocal
import models

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# SPRAWDŹ CZY BAZA ISTNIEJE ZANIM JĄ TWORZYSZ
if not os.path.exists("ctf_platform.db"):
    Base.metadata.create_all(bind=engine)
    print("Utworzono nowa baze danych")
else:
    print("Baza danych juz istnieje")
    # Nadal twórz tabele jeśli brakuje (np. dodano nowe kolumny)
    Base.metadata.create_all(bind=engine)

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ZEROFOUR_DIR = os.path.join(TEMPLATES_DIR, "zerofour")

app.mount("/assets", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "assets")), name="assets")
app.mount("/images", StaticFiles(directory=os.path.join(ZEROFOUR_DIR, "images")), name="images")

templates = Jinja2Templates(directory=TEMPLATES_DIR)


def init_database():
    db = SessionLocal()
    try:
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin:
            admin_user = models.User(username="admin", password_hash=get_password_hash("admin"))
            db.add(admin_user)
            db.commit()
            print("Utworzono konto admina (login: admin, haslo: admin)")
        else:
            print("Konto admina juz istnieje - pomijam.")
        
        if db.query(models.Challenge).count() == 0:
            zadania = [
                models.Challenge(
                    title="Tajemniczy plik",
                    description="Znajdź flagę ukrytą w tym pliku tekstowym.",
                    long_description="Podczas rutynowego audytu wewnętrznego jeden z pracowników działu IT natknął się na podejrzany plik tekstowy. Twierdzi, że znajduje się w nim coś, co może być kluczem do głębszego problemu, ale nie jest w stanie tego zweryfikować. Plik wygląda jak zwykły raport, ale coś jest w nim nie tak... Może to tylko przeoczenie, a może celowo ukryta informacja? Twoim zadaniem jest dokładne przeanalizowanie tego pliku i znalezienie flagi.",
                    hint="Pamiętaj, że poszukiwana flaga jest zaszyfrowana.",
                    category="Forensics",
                    points=50,
                    flag="CTF{flaga_pliku_flag.txt}"
                ),
                models.Challenge(
                    title="Szyfr Cezara",
                    description="Odszyfruj zaszyfrowaną wiadomość.",
                    long_description="Juliusz Cezar używał tego szyfru do komunikacji ze swoimi generałami. Polega on na przesunięciu każdej litery w alfabecie o stałą liczbę miejsc. Zaszyfrowana wiadomość: egact wq jgólxua. Twoim zadaniem jest odszyfrowanie tej wiadomości i znalezienie flagi. Flaga ma format: CTF{odszyfrowana_wiadomosc} (małymi literami, spacje zastąp podkreślnikami).",
                    hint="Kluczem do tego zadania jest liczba 3.",
                    category="Cryptography",
                    points=100,
                    flag="CTF{cezar_to_geniusz}"
                )
            ]
            db.add_all(zadania)
            db.commit()
            print("Dodano zadania: Tajemniczy plik, Szyfr Cezara")
        else:
            print("Zadania juz istnieja - pomijam.")
        
        # Wyświetl ilość użytkowników w bazie (diagnostyka)
        user_count = db.query(models.User).count()
        print(f"Liczba uzytkownikow w bazie: {user_count}")
        
    except Exception as e:
        print(f"Blad inicjalizacji: {e}")
    finally:
        db.close()

init_database()


def get_user_points(db: Session, username: str):
    """Pomocnicza funkcja do pobierania punktów użytkownika"""
    if username:
        user = db.query(models.User).filter(models.User.username == username).first()
        if user:
            return user.score
    return 0


@app.get("/")
def home(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    all_challenges = db.query(models.Challenge).all()
    user_points = get_user_points(db, logged_in_user)
    
    return templates.TemplateResponse(
        request, 
        "zerofour/index.html", 
        {
            "request": request, 
            "username": logged_in_user,
            "challenges": all_challenges,
            "user_points": user_points
        }
    )

@app.get("/register")
def show_register_form(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    user_points = get_user_points(db, logged_in_user)
    return templates.TemplateResponse(
        request, 
        "zerofour/register.html", 
        {"request": request, "username": logged_in_user, "user_points": user_points}
    )

@app.post("/register")
def register_user(
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
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/login")
def show_login_form(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    user_points = get_user_points(db, logged_in_user)
    return templates.TemplateResponse(
        request, 
        "zerofour/login.html", 
        {"request": request, "username": logged_in_user, "user_points": user_points}
    )

@app.post("/login")
def login_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Nieprawidłowy login lub hasło!")
    
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="logged_in_user", value=user.username)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("logged_in_user")
    return response

@app.get("/admin")
def show_admin_panel(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak dostępu! Tylko dla administratora.")
    
    all_challenges = db.query(models.Challenge).all()
    user_points = get_user_points(db, logged_in_user)
    
    return templates.TemplateResponse(
        request, 
        "zerofour/admin.html", 
        {"request": request, "username": logged_in_user, "challenges": all_challenges, "user_points": user_points}
    )

@app.post("/admin/add-challenge")
def add_challenge(
    title: str = Form(...),
    description: str = Form(...),
    long_description: str = Form(None),
    hint: str = Form(None),
    category: str = Form(...),
    points: int = Form(...),
    flag: str = Form(...),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnień!")
    
    new_challenge = models.Challenge(
        title=title,
        description=description,
        long_description=long_description or description,
        hint=hint,
        category=category,
        points=points,
        flag=flag
    )
    db.add(new_challenge)
    db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/delete-challenge")
def delete_challenge(
    challenge_id: int = Form(...),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnień!")
    
    challenge = db.query(models.Challenge).filter(models.Challenge.id == challenge_id).first()
    if challenge:
        db.delete(challenge)
        db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/edit-challenge")
def edit_challenge(
    challenge_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(...),
    long_description: str = Form(None),
    hint: str = Form(None),
    category: str = Form(...),
    points: int = Form(...),
    flag: str = Form(...),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnień!")
    
    challenge = db.query(models.Challenge).filter(models.Challenge.id == challenge_id).first()
    if challenge:
        challenge.title = title
        challenge.description = description
        challenge.long_description = long_description or description
        challenge.hint = hint
        challenge.category = category
        challenge.points = points
        challenge.flag = flag
        db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.get("/scoreboard")
def show_scoreboard(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    users = db.query(models.User).order_by(models.User.score.desc()).all()
    user_points = get_user_points(db, logged_in_user)
    
    return templates.TemplateResponse(
        request,
        "zerofour/scoreboard.html",
        {
            "request": request,
            "username": logged_in_user,
            "users": users,
            "user_points": user_points
        }
    )

@app.get("/rules")
def show_rules(request: Request, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    user_points = get_user_points(db, logged_in_user)
    return templates.TemplateResponse(
        request, 
        "zerofour/rules.html", 
        {"request": request, "username": logged_in_user, "user_points": user_points}
    )

@app.get("/challenge/{challenge_id}")
def show_challenge(request: Request, challenge_id: int, logged_in_user: str = Cookie(None), db: Session = Depends(get_db)):
    challenge = db.query(models.Challenge).filter(models.Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Zadanie nie istnieje!")
    
    user_points = get_user_points(db, logged_in_user)
    
    return templates.TemplateResponse(
        request,
        "zerofour/challenge.html",
        {
            "request": request,
            "username": logged_in_user,
            "challenge": challenge,
            "user_points": user_points
        }
    )

@app.get("/download/{challenge_id}")
def download_file(challenge_id: int):
    files_folder = os.path.join(BASE_DIR, "challenges_files")
    
    file_map = {
        1: "tajemniczy_plik.txt",
        2: "cezar.txt",
    }
    
    filename = file_map.get(challenge_id)
    if not filename:
        raise HTTPException(status_code=404, detail="Plik nie istnieje!")
    
    file_path = os.path.join(files_folder, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    
    raise HTTPException(status_code=404, detail="Plik nie istnieje!")

@app.post("/challenge/{challenge_id}/check")
def check_flag(
    request: Request,
    challenge_id: int,
    flag: str = Form(...),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    challenge = db.query(models.Challenge).filter(models.Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Zadanie nie istnieje!")
    
    user_points = get_user_points(db, logged_in_user)
    
    if not logged_in_user:
        return templates.TemplateResponse(
            request,
            "zerofour/challenge.html",
            {
                "request": request,
                "username": logged_in_user,
                "challenge": challenge,
                "message": "Musisz być zalogowany, aby zdobyć punkty!",
                "solved": False,
                "user_points": user_points
            }
        )
    
    user = db.query(models.User).filter(models.User.username == logged_in_user).first()
    if not user:
        return templates.TemplateResponse(
            request,
            "zerofour/challenge.html",
            {
                "request": request,
                "username": logged_in_user,
                "challenge": challenge,
                "message": "Nie znaleziono użytkownika!",
                "solved": False,
                "user_points": user_points
            }
        )
    
    existing_solve = db.query(models.Solve).filter(
        models.Solve.user_id == user.id,
        models.Solve.challenge_id == challenge.id
    ).first()
    
    if existing_solve:
        return templates.TemplateResponse(
            request,
            "zerofour/challenge.html",
            {
                "request": request,
                "username": logged_in_user,
                "challenge": challenge,
                "message": f"Już rozwiązałeś to zadanie!",
                "solved": True,
                "user_points": user_points
            }
        )
    
    if flag.strip() == challenge.flag:
        user.score += challenge.points
        new_solve = models.Solve(
            user_id=user.id,
            challenge_id=challenge.id
        )
        db.add(new_solve)
        db.commit()
        
        user_points = user.score
        
        return templates.TemplateResponse(
            request,
            "zerofour/challenge.html",
            {
                "request": request,
                "username": logged_in_user,
                "challenge": challenge,
                "message": f"Poprawna flaga! +{challenge.points} punktów!",
                "solved": True,
                "user_points": user_points
            }
        )
    else:
        return templates.TemplateResponse(
            request,
            "zerofour/challenge.html",
            {
                "request": request,
                "username": logged_in_user,
                "challenge": challenge,
                "message": "Niepoprawna flaga! Spróbuj ponownie.",
                "solved": False,
                "user_points": user_points
            }
        )