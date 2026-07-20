"""
Fixtures partagées pour tous les tests.
IMPORTANT : utilise une base SQLite en mémoire (ne touche pas à PostgreSQL).
"""
import pytest
from app import create_app
from models import db as _db
from models import User, Account
from utils import hash_password

@pytest.fixture(scope='function')
def app():
    """Fixture d'application Flask (recréée pour chaque test)"""
    app = create_app()

    # Remplacer l'URI de la base de données par SQLite en mémoire
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'IMAGE_GALLERY': {'landscape1', 'landscape2', 'cat1', 'cat2'},
        'IMAGE_CHALLENGE_TTL': 120,
        'MAX_FAILED_LOGIN_ATTEMPTS': 5,
        'ACCOUNT_LOCKOUT_MINUTES': 15,
        'TRANSACTION_VALIDATION_THRESHOLD': 10000,
    })

    with app.app_context():
        _db.create_all()   # Crée les tables dans la base mémoire
        yield app
        _db.drop_all()     # Nettoie après le test

@pytest.fixture
def client(app):
    """Client HTTP pour les tests d'intégration"""
    return app.test_client()

@pytest.fixture
def db_session(app):
    """Session de base de données pour les tests unitaires"""
    return _db.session

@pytest.fixture
def sample_user(db_session):
    """Crée un utilisateur standard pour les tests"""
    user = User(
        email='alice@example.com',
        password_hash=hash_password('Test1234!'),
        first_name='Alice',
        last_name='Dupont',
        role='client',
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user

@pytest.fixture
def admin_user(db_session):
    """Crée un administrateur pour les tests"""
    admin = User(
        email='admin@example.com',
        password_hash=hash_password('Admin1234!'),
        first_name='Admin',
        last_name='Super',
        role='admin',
        is_active=True
    )
    db_session.add(admin)
    db_session.commit()
    return admin

@pytest.fixture
def sample_account(db_session, sample_user):
    """Crée un compte courant pour l'utilisateur sample_user"""
    from services import create_account
    account = create_account(sample_user.id, 'current', 'XAF')
    account.balance = 1000.00
    db_session.commit()
    return account

@pytest.fixture
def auth_headers(client, sample_user):
    """En-têtes avec token JWT pour l'utilisateur sample_user"""
    resp = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'Test1234!'
    })
    token = resp.json['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def admin_headers(client, admin_user):
    """En-têtes avec token JWT pour l'admin"""
    resp = client.post('/api/v1/auth/login', json={
        'email': 'admin@example.com',
        'password': 'Admin1234!'
    })
    token = resp.json['access_token']
    return {'Authorization': f'Bearer {token}'}