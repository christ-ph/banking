import bcrypt
import hashlib
import re
import json
from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from models import db, AuditLog

def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def hash_fingerprint(minutiae_b64: str) -> str:
    """Hash les données d'empreinte (ne jamais stocker en clair)."""
    return hashlib.sha256(minutiae_b64.encode()).hexdigest()

def validate_password_strength(password: str):
    """Vérifie la robustesse du mot de passe."""
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if not re.search(r'[A-Z]', password):
        return False, "Doit contenir une majuscule"
    if not re.search(r'[a-z]', password):
        return False, "Doit contenir une minuscule"
    if not re.search(r'[0-9]', password):
        return False, "Doit contenir un chiffre"
    return True, "OK"

def admin_required(f):
    """Décorateur pour vérifier le rôle admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        from models import User
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def log_action(action, entity_type, entity_id, user_id, details=None):
    """Enregistre une action dans l'audit log."""
    log = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        details=json.dumps(details) if details else None,
        user_id=user_id
    )
    db.session.add(log)
    db.session.commit()

# ---- Fonctions supplémentaires utilisées par services.py ----
def generate_transaction_ref() -> str:
    """Génère une référence unique pour une transaction."""
    import time
    import random
    return f"TXN{int(time.time())}{random.randint(100, 999)}"

def generate_account_number() -> str:
    """Génère un numéro de compte aléatoire (16 chiffres)."""
    import random
    import string
    return ''.join(random.choices(string.digits, k=16))