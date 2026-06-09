# models.py
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)  # Tu będziemy trzymać zaszyfrowane hasło
    score = Column(Integer, default=0)              # Liczba punktów gracza
    
    # Relacja: jeden użytkownik może mieć wiele rozwiązanych zadań
    solves = relationship("Solve", back_populates="user")

class Challenge(Base):
    __tablename__ = "challenges"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    category = Column(String, nullable=False)        # Web, Crypto, Forensics
    points = Column(Integer, nullable=False)         # Wartość punktowa zadania
    flag = Column(String, nullable=False)            # Poprawna flaga, np. CTF{coś_tam}
    
    # Relacja: jedno zadanie może być rozwiązane przez wielu użytkowników
    solves = relationship("Solve", back_populates="challenge")

class Solve(Base):
    __tablename__ = "solves"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow) # Kiedy rozwiązano

    # Te linijki pozwalają łatwo wyciągać dane powiązane
    user = relationship("User", back_populates="solves")
    challenge = relationship("Challenge", back_populates="solves")