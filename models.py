"""
Modèles SQLAlchemy — Système bancaire complet.
Tables : User, Account, Transaction, Beneficiary,
         Company, License, UsageMetric, Invoice, AuditLog
"""
import uuid
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def _uuid():
    return str(uuid.uuid4())

def _now():
    return datetime.now(timezone.utc)

# ── Company (entreprise cliente / licence) ────────────────────────────────────
class Company(db.Model):
    __tablename__ = 'companies'

    id          = db.Column(db.String(36), primary_key=True, default=_uuid)
    name        = db.Column(db.String(200), nullable=False)
    siret       = db.Column(db.String(20), unique=True)
    country     = db.Column(db.String(3), default='CM')
    email       = db.Column(db.String(120))
    phone       = db.Column(db.String(25))
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=_now)

    users       = db.relationship('User',        back_populates='company', lazy='dynamic')
    license     = db.relationship('License',     back_populates='company', uselist=False)
    usage_metrics = db.relationship('UsageMetric', back_populates='company', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name,
            'country': self.country, 'is_active': self.is_active
        }

# ── User ─────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'

    id               = db.Column(db.String(36), primary_key=True, default=_uuid)
    email            = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash    = db.Column(db.String(255))
    fingerprint_hash = db.Column(db.String(512))         # Empreinte digitale (template)
    first_name       = db.Column(db.String(100))
    last_name        = db.Column(db.String(100))
    phone            = db.Column(db.String(25))
    role             = db.Column(db.String(20), default='client')
    is_active        = db.Column(db.Boolean, default=True)
    auth_methods     = db.Column(db.String(30), default='password')  # password|fingerprint|image|both|multi

    # --- Nouveaux champs pour l'authentification par image (FR-3) ---
    image_auth_enabled = db.Column(db.Boolean, default=False)
    image_reference_id = db.Column(db.String(50))          # ID de l'image choisie (ex: 'cat1')
    image_click_zone   = db.Column(db.Text)                # JSON : {"x":120, "y":340, "radius":15}
    # -----------------------------------------------------------------

    # --- WebAuthn / empreinte digitale (FR-4) ---
    webauthn_credential_id = db.Column(db.Text)            # stocké en base64
    webauthn_public_key    = db.Column(db.Text)
    webauthn_sign_count    = db.Column(db.Integer, default=0)
    # --------------------------------------------

    failed_attempts  = db.Column(db.Integer, default=0)
    locked_until     = db.Column(db.DateTime(timezone=True))
    company_id       = db.Column(db.String(36), db.ForeignKey('companies.id'))
    created_at       = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at       = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    company      = db.relationship('Company', back_populates='users')
    accounts     = db.relationship('Account', back_populates='user', lazy='dynamic')
    audit_logs   = db.relationship('AuditLog', back_populates='user', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email,
            'first_name': self.first_name, 'last_name': self.last_name,
            'role': self.role, 'is_active': self.is_active,
            'auth_methods': self.auth_methods,
            'image_auth_enabled': self.image_auth_enabled
        }

# ── Account, Transaction, etc. (inchangés) ────────────────────────────────────
class Account(db.Model):
    __tablename__ = 'accounts'
    id             = db.Column(db.String(36), primary_key=True, default=_uuid)
    account_number = db.Column(db.String(34), unique=True, nullable=False, index=True)
    account_type   = db.Column(db.String(20), default='current')
    balance        = db.Column(db.Numeric(15, 2), default=0)
    currency       = db.Column(db.String(3), default='XAF')
    is_active      = db.Column(db.Boolean, default=True)
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at     = db.Column(db.DateTime(timezone=True), default=_now)

    user            = db.relationship('User', back_populates='accounts')
    sent_transactions     = db.relationship('Transaction',
                                foreign_keys='Transaction.from_account_id',
                                back_populates='from_account', lazy='dynamic')
    received_transactions = db.relationship('Transaction',
                                foreign_keys='Transaction.to_account_id',
                                back_populates='to_account', lazy='dynamic')
    beneficiaries   = db.relationship('Beneficiary', back_populates='account', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id, 'account_number': self.account_number,
            'account_type': self.account_type,
            'balance': float(self.balance), 'currency': self.currency,
            'is_active': self.is_active
        }

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id              = db.Column(db.String(36), primary_key=True, default=_uuid)
    reference       = db.Column(db.String(50), unique=True, nullable=False)
    amount          = db.Column(db.Numeric(15, 2), nullable=False)
    currency        = db.Column(db.String(3), default='XAF')
    transaction_type = db.Column(db.String(20))
    status          = db.Column(db.String(20), default='pending')
    description     = db.Column(db.String(255))
    requires_validation = db.Column(db.Boolean, default=False)
    validated_by    = db.Column(db.String(36), db.ForeignKey('users.id'))
    from_account_id = db.Column(db.String(36), db.ForeignKey('accounts.id'))
    to_account_id   = db.Column(db.String(36), db.ForeignKey('accounts.id'))
    created_at      = db.Column(db.DateTime(timezone=True), default=_now)
    completed_at    = db.Column(db.DateTime(timezone=True))

    from_account = db.relationship('Account', foreign_keys=[from_account_id],
                                   back_populates='sent_transactions')
    to_account   = db.relationship('Account', foreign_keys=[to_account_id],
                                   back_populates='received_transactions')

    def to_dict(self):
        return {
            'id': self.id, 'reference': self.reference,
            'amount': float(self.amount), 'currency': self.currency,
            'type': self.transaction_type, 'status': self.status,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Beneficiary(db.Model):
    __tablename__ = 'beneficiaries'
    id             = db.Column(db.String(36), primary_key=True, default=_uuid)
    alias          = db.Column(db.String(100))
    account_number = db.Column(db.String(34), nullable=False)
    bank_name      = db.Column(db.String(100))
    is_active      = db.Column(db.Boolean, default=True)
    account_id     = db.Column(db.String(36), db.ForeignKey('accounts.id'), nullable=False)
    created_at     = db.Column(db.DateTime(timezone=True), default=_now)

    account = db.relationship('Account', back_populates='beneficiaries')

class License(db.Model):
    __tablename__ = 'licenses'
    id            = db.Column(db.String(36), primary_key=True, default=_uuid)
    license_key   = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan          = db.Column(db.String(20), default='starter')
    status        = db.Column(db.String(20), default='active')
    max_txn_month = db.Column(db.Integer, default=5000)
    starts_at     = db.Column(db.DateTime(timezone=True), default=_now)
    expires_at    = db.Column(db.DateTime(timezone=True))
    company_id    = db.Column(db.String(36), db.ForeignKey('companies.id'), unique=True)
    created_at    = db.Column(db.DateTime(timezone=True), default=_now)

    company = db.relationship('Company', back_populates='license')

    def is_valid(self):
        if self.status != 'active':
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

class UsageMetric(db.Model):
    __tablename__ = 'usage_metrics'
    id            = db.Column(db.String(36), primary_key=True, default=_uuid)
    month         = db.Column(db.String(7))
    txn_count     = db.Column(db.Integer, default=0)
    txn_volume    = db.Column(db.Numeric(18, 2), default=0)
    company_id    = db.Column(db.String(36), db.ForeignKey('companies.id'), nullable=False)
    created_at    = db.Column(db.DateTime(timezone=True), default=_now)

    company = db.relationship('Company', back_populates='usage_metrics')

class Invoice(db.Model):
    __tablename__ = 'invoices'
    id            = db.Column(db.String(36), primary_key=True, default=_uuid)
    invoice_number = db.Column(db.String(30), unique=True, nullable=False)
    amount        = db.Column(db.Numeric(15, 2), nullable=False)
    currency      = db.Column(db.String(3), default='XAF')
    status        = db.Column(db.String(20), default='pending')
    period        = db.Column(db.String(7))
    company_id    = db.Column(db.String(36), db.ForeignKey('companies.id'), nullable=False)
    issued_at     = db.Column(db.DateTime(timezone=True), default=_now)
    paid_at       = db.Column(db.DateTime(timezone=True))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id          = db.Column(db.String(36), primary_key=True, default=_uuid)
    action      = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id   = db.Column(db.String(36))
    ip_address  = db.Column(db.String(45))
    user_agent  = db.Column(db.String(255))
    details     = db.Column(db.Text)
    user_id     = db.Column(db.String(36), db.ForeignKey('users.id'))
    created_at  = db.Column(db.DateTime(timezone=True), default=_now)

    user = db.relationship('User', back_populates='audit_logs')