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

if not os.path.exists("ctf_platform.db"):
    Base.metadata.create_all(bind=engine)
    print("Utworzono nowa baze danych")
else:
    print("Baza danych juz istnieje")
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
                    description="Znajdz flage ukryta w tym pliku tekstowym.",
                    long_description="Podczas rutynowego audytu wewnetrznego jeden z pracownikow dzialu IT natknal sie na podejrzany plik tekstowy. Twierdzi, ze znajduje sie w nim cos, co moze byc kluczem do glebszego problemu, ale nie jest w stanie tego zweryfikowac. Plik wyglada jak zwykly raport, ale cos jest w nim nie tak... Moze to tylko przeoczenie, a moze celowo ukryta informacja? Twoim zadaniem jest dokladne przeanalizowanie tego pliku i znalezienie flagi.",
                    hint="Pamietaj, ze poszukiwana flaga jest zaszyfrowana.",
                    category="Forensics",
                    points=50,
                    flag="CTF{flaga_pliku_flag.txt}",
                    external_url=None
                ),
                models.Challenge(
                    title="Szyfr Cezara",
                    description="Odszyfruj zaszyfrowana wiadomosc.",
                    long_description="Juliusz Cezar uzywal tego szyfru do komunikacji ze swoimi generalami. Polega on na przesunieciu kazdej litery w alfabecie o stala liczbe miejsc. Zaszyfrowana wiadomosc: egact wq jgolxua. Twoim zadaniem jest odszyfrowanie tej wiadomosci i znalezienie flagi. Flaga ma format: CTF{odszyfrowana_wiadomosc} (malymi literami, spacje zastap podkreslnikami).",
                    hint="Kluczem do tego zadania jest liczba 3.",
                    category="Cryptography",
                    points=100,
                    flag="CTF{cezar_to_geniusz}",
                    external_url=None
                ),
                models.Challenge(
                    title="Podatna wyszukiwarka",
                    description="Znajdz luke w wyszukiwarce produktow i zdobadz flage.",
                    long_description="Firma CyberShop uruchomila wlasnie swoja nowa platforme e-commerce. Niestety, ktos zapomnial o zabezpieczeniach... Wyszukiwarka produktow jest podatna na SQL Injection. Twoim zadaniem jest ominiecie zabezpieczen i wyswietlenie wszystkich produktow, w tym ukrytego, ktory zawiera flage.",
                    hint="Sprobuj wpisac cos w pole wyszukiwania, co sprawi, ze baza danych pokaze wszystko.",
                    category="Web Exploitation",
                    points=150,
                    flag="CTF{sql_injection_master}",
                    external_url="http://127.0.0.1:5000"
                )
            ]
            db.add_all(zadania)
            db.commit()
            print("Dodano zadania: Tajemniczy plik, Szyfr Cezara, Podatna wyszukiwarka")
        else:
            print("Zadania juz istnieja - pomijam.")
        
        user_count = db.query(models.User).count()
        print(f"Liczba uzytkownikow w bazie: {user_count}")
        
    except Exception as e:
        print(f"Blad inicjalizacji: {e}")
    finally:
        db.close()

init_database()


def get_user_points(db: Session, username: str):
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
        raise HTTPException(status_code=400, detail="Nazwa uzytkownika jest juz zajeta!")
    
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
        raise HTTPException(status_code=400, detail="Nieprawidlowy login lub haslo!")
    
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
        raise HTTPException(status_code=403, detail="Brak dostepu! Tylko dla administratora.")
    
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
    external_url: str = Form(None),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnien!")
    
    new_challenge = models.Challenge(
        title=title,
        description=description,
        long_description=long_description or description,
        hint=hint,
        category=category,
        points=points,
        flag=flag,
        external_url=external_url
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
        raise HTTPException(status_code=403, detail="Brak uprawnien!")
    
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
    external_url: str = Form(None),
    logged_in_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not logged_in_user or logged_in_user != "admin":
        raise HTTPException(status_code=403, detail="Brak uprawnien!")
    
    challenge = db.query(models.Challenge).filter(models.Challenge.id == challenge_id).first()
    if challenge:
        challenge.title = title
        challenge.description = description
        challenge.long_description = long_description or description
        challenge.hint = hint
        challenge.category = category
        challenge.points = points
        challenge.flag = flag
        challenge.external_url = external_url
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
                "message": "Musisz byc zalogowany, aby zdobyc punkty!",
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
                "message": "Nie znaleziono uzytkownika!",
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
                "message": "Juz rozwiazales to zadanie!",
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
                "message": f"Poprawna flaga! +{challenge.points} punktow!",
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
                "message": "Niepoprawna flaga! Sprobuj ponownie.",
                "solved": False,
                "user_points": user_points
            }
        )