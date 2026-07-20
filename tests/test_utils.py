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
