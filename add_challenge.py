from database import SessionLocal
import models

db = SessionLocal()

# Sprawdzamy czy zadanie już istnieje (żeby nie dodać drugi raz)
existing = db.query(models.Challenge).filter(models.Challenge.title == "Tajemniczy plik").first()
if existing:
    print("Zadanie już istnieje!")
else:
    new_challenge = models.Challenge(
        title="Tajemniczy plik",
        description="Znajdź flagę ukrytą w tym pliku tekstowym.",
        category="Forensics",
        points=50,
        flag="CTF{flaga_pliku_flag.txt}"
    )
    db.add(new_challenge)
    db.commit()
    print("Dodano zadanie: Tajemniczy plik")

db.close()