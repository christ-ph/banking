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
