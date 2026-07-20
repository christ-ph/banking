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
