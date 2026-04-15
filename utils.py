"""
Utilitaires : hash, validation, audit, génération de références.

CORRECTIONS :
  - hash_fingerprint : bcrypt au lieu de SHA-256 simple (SHA-256 non salé est réversible)
  - check_fingerprint ajouté (manquait dans la version originale)
  - log_action : commit() supprimé — la route appelante gère le commit global
    (double commit causait des erreurs de transaction en cascade)
  - generate_account_number : format camerounais CM + 23 chiffres
"""
import bcrypt
import re
import json
import uuid
import time
import random
import string
from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request


# ── Mot de passe ──────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def validate_password_strength(password: str):
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if not re.search(r'[A-Z]', password):
        return False, "Doit contenir une majuscule"
    if not re.search(r'[a-z]', password):
        return False, "Doit contenir une minuscule"
    if not re.search(r'[0-9]', password):
        return False, "Doit contenir un chiffre"
    return True, "OK"


# ── Empreinte digitale ────────────────────────────────────────────────────────
# CORRECTION : SHA-256 sans sel est réversible par rainbow table.
# On utilise bcrypt avec pepper pour protéger les minuties.

_FINGERPRINT_PEPPER = "banking_cm_pepper_2024"


def hash_fingerprint(minutiae_b64: str) -> str:
    """Hash les minuties d'empreinte avec bcrypt + pepper."""
    peppered = (minutiae_b64 + _FINGERPRINT_PEPPER).encode('utf-8')
    return bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=10)).decode('utf-8')


def check_fingerprint(minutiae_b64: str, stored_hash: str) -> bool:
    """Vérifie une empreinte contre son hash stocké."""
    peppered = (minutiae_b64 + _FINGERPRINT_PEPPER).encode('utf-8')
    return bcrypt.checkpw(peppered, stored_hash.encode('utf-8'))


# ── Génération de références ──────────────────────────────────────────────────

def generate_transaction_ref() -> str:
    """TXN-YYYYMMDD-XXXXXXXX (format lisible + unicité)."""
    from datetime import datetime, timezone
    date_part = datetime.now(timezone.utc).strftime('%Y%m%d')
    unique    = uuid.uuid4().hex[:8].upper()
    return f"TXN-{date_part}-{unique}"


def generate_account_number() -> str:
    """Numéro de compte format camerounais : CM + 23 chiffres."""
    digits = ''.join(random.choices(string.digits, k=23))
    return f"CM{digits}"


# ── Décorateurs ───────────────────────────────────────────────────────────────

def admin_required(f):
    """Vérifie que l'utilisateur JWT est admin ou operator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from models import User
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user    = User.query.get(user_id)
        if not user or user.role not in ('admin', 'operator'):
            return jsonify({"error": "Accès réservé aux administrateurs"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Audit ─────────────────────────────────────────────────────────────────────

def log_action(action: str, entity_type: str, entity_id, user_id, details=None):
    """
    Enregistre une action dans audit_logs.
    CORRECTION : plus de db.session.commit() ici — la route appelante commit globalement.
    Cela évite les erreurs de transaction imbriquée (InFailedSqlTransaction).
    """
    from models import db, AuditLog
    log = AuditLog(
        action      = action,
        entity_type = entity_type,
        entity_id   = str(entity_id) if entity_id else None,
        ip_address  = request.remote_addr if request else None,
        user_agent  = request.headers.get('User-Agent', '') if request else None,
        details     = json.dumps(details, ensure_ascii=False) if details else None,
        user_id     = user_id
    )
    db.session.add(log)
    # PAS de commit ici — le commit sera fait par la route après toutes les opérations