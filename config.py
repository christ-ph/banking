import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


def _build_db_url():
    """
    Construit l'URL de connexion PostgreSQL avec le dialecte psycopg3.
    La variable DATABASE_URL doit être définie dans l'environnement.
    """
    url = os.environ.get('DATABASE_URL')
    if not url:
        # Pas de fallback dangereux : on lève une erreur explicite
        raise RuntimeError("DATABASE_URL non définie. Veuillez la configurer.")
    
    # Remplacer postgres:// par postgresql:// si nécessaire
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    # Forcer l'utilisation du driver psycopg (psycopg3)
    if url.startswith('postgresql://') and '+psycopg' not in url:
        url = url.replace('postgresql://', 'postgresql+psycopg://', 1)
    return url


class Config:
    SECRET_KEY     = os.environ.get('SECRET_KEY', 'banking_secret_key_cameroun_2024')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'salutkamdoum')

    SQLALCHEMY_DATABASE_URI        = _build_db_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS      = {
        "pool_pre_ping": True,
        "pool_recycle":  300,
        "pool_size":     5,
        "max_overflow":  10,
        "connect_args":  {"sslmode": "require"},
    }

    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(minutes=120)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=15)
    JWT_TOKEN_LOCATION        = ['headers']
    JWT_HEADER_NAME           = 'Authorization'
    JWT_HEADER_TYPE           = 'Bearer'

    DOUBLE_VALIDATION_THRESHOLD      = 10_000
    TRANSACTION_VALIDATION_THRESHOLD = 10_000
    MAX_FAILED_LOGIN_ATTEMPTS        = 5
    ACCOUNT_LOCKOUT_MINUTES          = 15
    LICENSE_GRACE_DAYS               = 30
    MIN_PASSWORD_LENGTH              = 8

    IMAGE_GALLERY = {
        'landscape1', 'landscape2', 'cat1', 'cat2', 'car1', 'car2',
        'building1', 'building2', 'food1', 'food2', 'nature1', 'nature2'
    }
    IMAGE_CHALLENGE_TTL = 120

    WEBAUTHN_RP_ID   = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
    WEBAUTHN_RP_NAME = "Banque Multifacteurs"
    WEBAUTHN_ORIGIN  = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False

    @classmethod
    def init_app(cls, app):
        # Vérifications strictes en production
        assert os.environ.get('DATABASE_URL'), "DATABASE_URL non définie en production !"
        assert os.environ.get('SECRET_KEY'), "SECRET_KEY non définie en production !"
        assert os.environ.get('JWT_SECRET_KEY'), "JWT_SECRET_KEY non définie en production !"


config = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig,
}