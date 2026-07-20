#!/bin/bash
# Script de création des fichiers de test pour le projet bancaire
# À placer à la racine du projet et exécuter avec : bash create_test_files.sh

set -e  # Arrêt en cas d'erreur

# Création du dossier tests
mkdir -p tests

# ============================================================
# 1. tests/__init__.py
# ============================================================
cat > tests/__init__.py << 'EOF'
# Rendre le dossier 'tests' un package Python
EOF

# ============================================================
# 2. tests/conftest.py
# ============================================================
cat > tests/conftest.py << 'EOF'
"""
Fixtures partagées pour tous les tests.
Utilise une base SQLite en mémoire pour les tests.
"""
import pytest
import tempfile
import json
from datetime import datetime, timezone
from app import create_app
from models import db as _db
from models import User, Account
from utils import hash_password

@pytest.fixture(scope='session')
def app():
    """Fixture d'application Flask (session)"""
    app = create_app()
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
        _db.create_all()
        yield app
        _db.drop_all()

@pytest.fixture
def client(app):
    """Client HTTP pour les tests d'intégration"""
    return app.test_client()

@pytest.fixture
def db_session(app):
    """Session de base de données pour les tests unitaires"""
    with app.app_context():
        yield _db.session

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
    # Forcer un solde initial pour les tests
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
EOF

# ============================================================
# 3. tests/test_utils.py
# ============================================================
cat > tests/test_utils.py << 'EOF'
import pytest
from utils import (
    hash_password, verify_password, validate_password_strength,
    hash_fingerprint, check_fingerprint,
    generate_transaction_ref, generate_account_number,
    log_action
)
from models import db, AuditLog

def test_hash_password():
    pwd = "Secret123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed)
    assert not verify_password("Wrong", hashed)

def test_validate_password_strength():
    valid, msg = validate_password_strength("Abc12345")
    assert valid
    valid, msg = validate_password_strength("short")
    assert not valid
    valid, msg = validate_password_strength("nouppercase1")
    assert not valid
    valid, msg = validate_password_strength("NOLOWER123")
    assert not valid
    valid, msg = validate_password_strength("NoDigit!")
    assert not valid

def test_fingerprint_hash():
    minutiae = "base64_fake_minutiae"
    hashed = hash_fingerprint(minutiae)
    assert check_fingerprint(minutiae, hashed)
    assert not check_fingerprint("different", hashed)

def test_generate_transaction_ref():
    ref = generate_transaction_ref()
    assert ref.startswith("TXN-")
    assert len(ref) == len("TXN-YYYYMMDD-XXXXXXXX")  # ~24

def test_generate_account_number():
    acc = generate_account_number()
    assert acc.startswith("CM")
    assert len(acc) == 25  # CM + 23 chiffres
    assert acc[2:].isdigit()

def test_log_action(db_session, sample_user):
    # log_action ajoute un audit log sans commit automatique
    log_action('test_action', 'user', sample_user.id, sample_user.id, details={'key': 'value'})
    # On doit commit manuellement dans les tests (sinon la session est propre)
    db_session.commit()
    log = AuditLog.query.filter_by(action='test_action').first()
    assert log is not None
    assert log.user_id == sample_user.id
EOF

# ============================================================
# 4. tests/test_services.py
# ============================================================
cat > tests/test_services.py << 'EOF'
import pytest
import json
from datetime import datetime, timedelta, timezone
from services import (
    verify_login, verify_fingerprint_login,
    create_account, process_transfer,
    get_image_challenge, verify_image_response,
    generate_webauthn_registration_challenge, verify_webauthn_registration,
    generate_webauthn_login_challenge, verify_webauthn_login,
    image_challenge_store, webauthn_challenge_store
)
from models import User, Account, Transaction
from utils import hash_password, hash_fingerprint

def test_verify_login_success(db_session, sample_user):
    user, error = verify_login('alice@example.com', 'Test1234!')
    assert error is None
    assert user.id == sample_user.id

def test_verify_login_wrong_password(db_session, sample_user):
    user, error = verify_login('alice@example.com', 'wrong')
    assert user is None
    assert error == "Identifiants invalides"
    # Vérifier que failed_attempts a augmenté
    user_db = User.query.get(sample_user.id)
    assert user_db.failed_attempts == 1

def test_verify_login_locked(db_session, sample_user, app):
    with app.app_context():
        # Simuler 5 échecs
        for _ in range(5):
            verify_login('alice@example.com', 'wrong')
        user, error = verify_login('alice@example.com', 'Test1234!')
        assert user is None
        assert "verrouillé" in error

def test_verify_fingerprint_login(db_session, sample_user):
    minutiae = "fake_minutiae"
    sample_user.fingerprint_hash = hash_fingerprint(minutiae)
    db_session.commit()
    user, error = verify_fingerprint_login(sample_user.id, minutiae)
    assert error is None
    assert user.id == sample_user.id

def test_verify_fingerprint_login_invalid(db_session, sample_user):
    sample_user.fingerprint_hash = hash_fingerprint("good")
    db_session.commit()
    user, error = verify_fingerprint_login(sample_user.id, "bad")
    assert user is None
    assert error == "Empreinte invalide"

def test_create_account(db_session, sample_user):
    acc = create_account(sample_user.id, 'savings', 'EUR')
    assert acc.account_number.startswith('CM')
    assert acc.user_id == sample_user.id
    assert acc.balance == 0

def test_process_transfer_success(db_session, sample_user, sample_account):
    # Créer un second compte pour la destination
    to_account = create_account(sample_user.id, 'current', 'XAF')
    db_session.commit()
    txn, error = process_transfer(
        from_account_id=sample_account.id,
        to_account_id=to_account.id,
        amount=100,
        description="Test",
        initiated_by=sample_user.id
    )
    assert error is None
    assert txn.status == 'completed'
    # Vérifier les soldes
    db_session.refresh(sample_account)
    db_session.refresh(to_account)
    assert sample_account.balance == 900.0  # 1000 - 100
    assert to_account.balance == 100.0

def test_process_transfer_insufficient_funds(db_session, sample_user, sample_account):
    to_account = create_account(sample_user.id, 'current', 'XAF')
    txn, error = process_transfer(
        from_account_id=sample_account.id,
        to_account_id=to_account.id,
        amount=2000,
        description="Too much",
        initiated_by=sample_user.id
    )
    assert txn is None
    assert error == "Solde insuffisant"

def test_process_transfer_wrong_owner(db_session, sample_user, sample_account, admin_user):
    # Tentative de transfert depuis un compte qui n'appartient pas à l'initiateur
    to_account = create_account(admin_user.id, 'current', 'XAF')
    txn, error = process_transfer(
        from_account_id=to_account.id,  # compte de l'admin
        to_account_id=sample_account.id,
        amount=10,
        description="Fraud",
        initiated_by=sample_user.id
    )
    assert txn is None
    assert error == "Vous n'êtes pas propriétaire du compte source"

def test_process_transfer_above_threshold(db_session, sample_user, sample_account, app):
    with app.app_context():
        to_account = create_account(sample_user.id, 'current', 'XAF')
        txn, error = process_transfer(
            from_account_id=sample_account.id,
            to_account_id=to_account.id,
            amount=15000,
            description="Big transfer",
            initiated_by=sample_user.id
        )
        assert error is None
        assert txn.status == 'pending'
        assert txn.requires_validation is True
        # Soldes inchangés
        db_session.refresh(sample_account)
        assert sample_account.balance == 1000.0

def test_image_challenge_flow(db_session, sample_user, app):
    with app.app_context():
        sample_user.image_auth_enabled = True
        sample_user.image_reference_id = 'landscape1'
        sample_user.image_click_zone = json.dumps({'x': 100, 'y': 200, 'radius': 15})
        db_session.commit()

        challenge_data, err = get_image_challenge(sample_user.id)
        assert err is None
        assert 'challenge_id' in challenge_data
        assert len(challenge_data['images']) == 3

        cid = challenge_data['challenge_id']
        ok, msg, user_id = verify_image_response(cid, 'landscape1', 100, 200)
        assert ok
        assert user_id == sample_user.id

def test_webauthn_flow(db_session, sample_user):
    challenge = generate_webauthn_registration_challenge(sample_user)
    assert challenge in webauthn_challenge_store
    # Simuler registration
    cred_data = {'credential_id': 'cred123', 'public_key': 'pubkey456'}
    ok, msg = verify_webauthn_registration(challenge, cred_data)
    assert ok
    db_session.refresh(sample_user)
    assert sample_user.webauthn_credential_id == 'cred123'
    assert sample_user.webauthn_public_key == 'pubkey456'
    # Login challenge
    login_challenge = generate_webauthn_login_challenge(sample_user)
    ok, msg, user_id = verify_webauthn_login(login_challenge, 'fake_signature')
    assert ok
    assert user_id == sample_user.id
EOF

# ============================================================
# 5. tests/test_models.py
# ============================================================
cat > tests/test_models.py << 'EOF'
from models import User, Account, Transaction, AuditLog, Company
from utils import hash_password
from datetime import datetime, timezone

def test_create_user(db_session):
    user = User(email='bob@example.com', password_hash=hash_password('Pass123!'))
    db_session.add(user)
    db_session.commit()
    assert user.id is not None
    assert user.created_at is not None

def test_user_account_relationship(db_session, sample_user):
    from services import create_account
    acc1 = create_account(sample_user.id, 'current', 'XAF')
    acc2 = create_account(sample_user.id, 'savings', 'XAF')
    db_session.commit()
    assert sample_user.accounts.count() == 2

def test_transaction_relationships(db_session, sample_user, sample_account):
    from services import create_account, process_transfer
    to_acc = create_account(sample_user.id, 'current', 'XAF')
    txn, _ = process_transfer(sample_account.id, to_acc.id, 50, "test", sample_user.id)
    db_session.commit()
    assert txn.from_account.id == sample_account.id
    assert txn.to_account.id == to_acc.id
    assert sample_account.sent_transactions.count() == 1
    assert to_acc.received_transactions.count() == 1

def test_audit_log(db_session, sample_user):
    log = AuditLog(
        action='login',
        entity_type='user',
        entity_id=sample_user.id,
        user_id=sample_user.id,
        ip_address='127.0.0.1'
    )
    db_session.add(log)
    db_session.commit()
    assert sample_user.audit_logs.count() == 1

def test_company_license(db_session):
    company = Company(name='Test Corp', siret='123456789')
    db_session.add(company)
    db_session.commit()
    assert company.license is None
    from models import License
    lic = License(license_key='KEY123', plan='pro', company_id=company.id)
    db_session.add(lic)
    db_session.commit()
    assert company.license.license_key == 'KEY123'
EOF

# ============================================================
# 6. tests/test_routes_auth.py
# ============================================================
cat > tests/test_routes_auth.py << 'EOF'
def test_register_success(client, db_session):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'newuser@example.com',
        'password': 'StrongP@ss1',
        'first_name': 'New',
        'last_name': 'User'
    })
    assert resp.status_code == 201
    assert 'user_id' in resp.json

def test_register_weak_password(client):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'weak@example.com',
        'password': 'weak'
    })
    assert resp.status_code == 400
    assert 'caractères' in resp.json['error']

def test_register_duplicate_email(client, sample_user):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'alice@example.com',
        'password': 'Another123!'
    })
    assert resp.status_code == 409
    assert 'déjà utilisé' in resp.json['error']

def test_login_success(client, sample_user):
    resp = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'Test1234!'
    })
    assert resp.status_code == 200
    assert 'access_token' in resp.json
    assert resp.json['user']['email'] == 'alice@example.com'

def test_login_invalid(client, sample_user):
    resp = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'wrong'
    })
    assert resp.status_code == 401
    assert resp.json['error'] == 'Identifiants invalides'

def test_refresh_token(client, sample_user):
    # D'abord login
    login = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'Test1234!'
    })
    refresh = login.json['refresh_token']
    resp = client.post('/api/v1/auth/refresh', headers={
        'Authorization': f'Bearer {refresh}'
    })
    assert resp.status_code == 200
    assert 'access_token' in resp.json

def test_image_enrollment(client, auth_headers, sample_user):
    resp = client.post('/api/v1/auth/image/enroll', headers=auth_headers, json={
        'image_id': 'landscape1',
        'click_zone': {'x': 150, 'y': 250, 'radius': 20}
    })
    assert resp.status_code == 200
    assert sample_user.image_auth_enabled is True

def test_image_login_flow(client, sample_user, db_session):
    # Préparer l'utilisateur avec image
    sample_user.image_auth_enabled = True
    sample_user.image_reference_id = 'landscape1'
    sample_user.image_click_zone = '{"x":100,"y":200,"radius":15}'
    db_session.commit()
    # Step1
    step1 = client.post('/api/v1/auth/login/image', json={'email': 'alice@example.com'})
    assert step1.status_code == 200
    challenge_id = step1.json['challenge_id']
    # Step2
    step2 = client.post('/api/v1/auth/login/image/verify', json={
        'challenge_id': challenge_id,
        'selected_image_id': 'landscape1',
        'click_x': 100,
        'click_y': 200
    })
    assert step2.status_code == 200
    assert 'access_token' in step2.json
EOF

# ============================================================
# 7. tests/test_routes_accounts.py
# ============================================================
cat > tests/test_routes_accounts.py << 'EOF'
def test_list_accounts_empty(client, auth_headers):
    resp = client.get('/api/v1/accounts', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json == []

def test_create_account(client, auth_headers, sample_user):
    resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'savings',
        'currency': 'USD'
    })
    assert resp.status_code == 201
    assert resp.json['account_type'] == 'savings'
    assert resp.json['currency'] == 'USD'

def test_get_account(client, auth_headers, sample_account):
    resp = client.get(f'/api/v1/accounts/{sample_account.id}', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json['id'] == sample_account.id

def test_get_account_not_found(client, auth_headers):
    resp = client.get('/api/v1/accounts/unknown-id', headers=auth_headers)
    assert resp.status_code == 404

def test_list_accounts_with_data(client, auth_headers, sample_account):
    resp = client.get('/api/v1/accounts', headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json) == 1
    assert resp.json[0]['account_number'] == sample_account.account_number
EOF

# ============================================================
# 8. tests/test_routes_transactions.py
# ============================================================
cat > tests/test_routes_transactions.py << 'EOF'
def test_transfer_success(client, auth_headers, sample_account):
    # Créer un second compte pour la destination
    create_resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'current'
    })
    to_account_id = create_resp.json['id']
    resp = client.post('/api/v1/transactions/transfer', headers=auth_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_account_id,
        'amount': 50,
        'description': 'Test transfer'
    })
    assert resp.status_code == 201
    assert 'Virement effectué' in resp.json['message']

def test_transfer_insufficient_funds(client, auth_headers, sample_account):
    create_resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'current'
    })
    to_account_id = create_resp.json['id']
    resp = client.post('/api/v1/transactions/transfer', headers=auth_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_account_id,
        'amount': 5000,
        'description': 'Too high'
    })
    assert resp.status_code == 400
    assert 'Solde insuffisant' in resp.json['error']

def test_deposit(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/deposit', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 200,
        'description': 'Cash deposit'
    })
    assert resp.status_code == 200
    assert resp.json['new_balance'] == 1200.0
    assert resp.json['transaction']['transaction_type'] == 'deposit'

def test_withdraw(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 100,
        'description': 'ATM withdrawal'
    })
    assert resp.status_code == 200
    assert resp.json['new_balance'] == 900.0

def test_withdraw_insufficient(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 2000
    })
    assert resp.status_code == 400
    assert 'Solde insuffisant' in resp.json['error']

def test_list_transactions(client, auth_headers, sample_account):
    # Faire quelques transactions
    client.post('/api/v1/transactions/deposit', headers=auth_headers, json={
        'account_id': sample_account.id, 'amount': 100
    })
    client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id, 'amount': 50
    })
    resp = client.get('/api/v1/transactions', headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json) >= 2
EOF

# ============================================================
# 9. tests/test_routes_admin.py
# ============================================================
cat > tests/test_routes_admin.py << 'EOF'
def test_admin_list_users_as_admin(client, admin_headers):
    resp = client.get('/api/v1/admin/users', headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json, list)

def test_admin_list_users_as_non_admin(client, auth_headers):
    resp = client.get('/api/v1/admin/users', headers=auth_headers)
    assert resp.status_code == 403

def test_admin_create_user(client, admin_headers):
    resp = client.post('/api/v1/admin/users', headers=admin_headers, json={
        'email': 'newclient@example.com',
        'password': 'Client123!',
        'role': 'client'
    })
    assert resp.status_code == 201
    assert resp.json['user']['email'] == 'newclient@example.com'

def test_admin_update_user(client, admin_headers, sample_user):
    resp = client.put(f'/api/v1/admin/users/{sample_user.id}', headers=admin_headers, json={
        'role': 'operator',
        'is_active': False
    })
    assert resp.status_code == 200
    assert resp.json['user']['role'] == 'operator'
    assert resp.json['user']['is_active'] is False

def test_admin_delete_user(client, admin_headers, sample_user):
    # Créer un utilisateur spécifique pour suppression
    create = client.post('/api/v1/admin/users', headers=admin_headers, json={
        'email': 'todelete@example.com', 'password': 'Delete123!'
    })
    user_id = create.json['user']['id']
    resp = client.delete(f'/api/v1/admin/users/{user_id}', headers=admin_headers)
    assert resp.status_code == 200
    assert 'désactivé' in resp.json['message']

def test_admin_validate_transaction(client, admin_headers, sample_account, sample_user):
    # Créer une transaction en attente (montant > seuil)
    # D'abord créer un compte destinataire
    to_acc = client.post('/api/v1/accounts', headers=admin_headers, json={'account_type': 'current'})
    to_id = to_acc.json['id']
    transfer = client.post('/api/v1/transactions/transfer', headers=admin_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_id,
        'amount': 15000,
        'description': 'Big'
    })
    txn_id = transfer.json['transaction']['id']
    # Validation admin
    resp = client.post(f'/api/v1/admin/transactions/{txn_id}/validate', headers=admin_headers)
    assert resp.status_code == 200
    assert 'Transaction validée' in resp.json['message']

def test_admin_audit_log(client, admin_headers):
    resp = client.get('/api/v1/admin/audit', headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json, list)
EOF

# ============================================================
# 10. tests/test_routes_profile.py
# ============================================================
cat > tests/test_routes_profile.py << 'EOF'
def test_get_my_profile(client, auth_headers, sample_user):
    resp = client.get('/api/v1/users/me', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json['email'] == sample_user.email

def test_update_my_profile(client, auth_headers, sample_user):
    resp = client.put('/api/v1/users/me', headers=auth_headers, json={
        'first_name': 'Alicia',
        'phone': '+237612345678'
    })
    assert resp.status_code == 200
    assert resp.json['user']['first_name'] == 'Alicia'
    assert resp.json['user']['phone'] == '+237612345678'
EOF

# ============================================================
# 11. pytest.ini
# ============================================================
cat > pytest.ini << 'EOF'
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --strict-markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
EOF

# ============================================================
# 12. run_tests.py
# ============================================================
cat > run_tests.py << 'EOF'
#!/usr/bin/env python3
"""
Script pour exécuter tous les tests et générer un rapport HTML.
Utilisation: python run_tests.py
"""
import pytest
import sys
import os
from datetime import datetime

if __name__ == "__main__":
    # Générer un nom de rapport avec horodatage
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"rapport_tests_{timestamp}.html"
    
    # Arguments pytest
    args = [
        "tests/",
        f"--html={report_file}",
        "--self-contained-html",
        "-v",
        "--tb=short",
        "--maxfail=5"
    ]
    
    print(f"🚀 Lancement des tests - Rapport : {report_file}")
    exit_code = pytest.main(args)
    
    if exit_code == 0:
        print(f"\n✅ Tous les tests ont réussi. Rapport généré : {report_file}")
    else:
        print(f"\n❌ Des tests ont échoué. Rapport généré : {report_file}")
    
    sys.exit(exit_code)
EOF

# Rendre run_tests.py exécutable
chmod +x run_tests.py

echo "=========================================="
echo "✅ Tous les fichiers de test ont été créés !"
echo "   Dossier 'tests' avec 10 fichiers"
echo "   Fichier pytest.ini"
echo "   Fichier run_tests.py"
echo ""
echo "Pour exécuter les tests :"
echo "  source venv/bin/activate"
echo "  pip install pytest pytest-html pytest-flask"
echo "  python run_tests.py"
echo "=========================================="