"""
Configuration de l'application bancaire.
Charge automatiquement le fichier .env via python-dotenv.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Charge .env AVANT tout os.environ.get()
load_dotenv()

class Config:
    # ── Clés secrètes ─────────────────────────────────────────────
    SECRET_KEY     = os.environ.get('SECRET_KEY', 'banking_secret_key_cameroun_2024')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'salutkamdoum')

    # ── Base de données ───────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://christ:123456@localhost:5432/bankdb'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle":  300,
        "connect_args":  {"connect_timeout": 10}
    }

    # ── JWT ───────────────────────────────────────────────────────
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_TOKEN_LOCATION        = ['headers']
    JWT_HEADER_NAME           = 'Authorization'
    JWT_HEADER_TYPE           = 'Bearer'

    # ── Règles métier bancaires ───────────────────────────────────
    DOUBLE_VALIDATION_THRESHOLD = 10_000   # XAF : seuil double validation
    MAX_FAILED_LOGIN_ATTEMPTS   = 5
    ACCOUNT_LOCKOUT_MINUTES     = 15
    LICENSE_GRACE_DAYS          = 30
    MIN_PASSWORD_LENGTH         = 8

    # ── Authentification par image (FR-3) ─────────────────────────
    # Galerie d'images (IDs correspondant aux fichiers dans static/gallery/)
    IMAGE_GALLERY = {
        'landscape1', 'landscape2', 'cat1', 'cat2', 'car1', 'car2',
        'building1', 'building2', 'food1', 'food2', 'nature1', 'nature2'
    }
    # Durée de validité d'un challenge image (secondes)
    IMAGE_CHALLENGE_TTL = 120

    # ── Authentification par empreinte / WebAuthn (FR-4) ──────────
    WEBAUTHN_RP_ID     = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
    WEBAUTHN_RP_NAME   = "Banque Multifacteurs"
    WEBAUTHN_ORIGIN    = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')

    # Seuil pour exiger empreinte sur transaction sensible
    TRANSACTION_VALIDATION_THRESHOLD = DOUBLE_VALIDATION_THRESHOLD

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    @classmethod
    def init_app(cls, app):
        assert os.environ.get('DATABASE_URL'), "DATABASE_URL non définie en production !"
        assert os.environ.get('SECRET_KEY'),   "SECRET_KEY non définie en production !"

config = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig
}