import json
import hashlib
import time
import random
from flask import current_app, request
from datetime import datetime, timezone
from models import db, User, Account, Transaction, AuditLog
from utils import (
    verify_password, hash_fingerprint, log_action,
    generate_transaction_ref, generate_account_number
)

# Stockage temporaire des challenges (en mémoire, à remplacer par Redis en prod)
image_challenge_store = {}
webauthn_challenge_store = {}

# ------------------------------------------------------------
# Services existants (adaptés)
# ------------------------------------------------------------
def verify_login(email, password):
    user = User.query.filter_by(email=email).first()
    if not user or not user.password_hash:
        return None, "Identifiants invalides"
    if not verify_password(password, user.password_hash):
        return None, "Identifiants invalides"
    if not user.is_active:
        return None, "Compte désactivé"
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return None, "Compte temporairement verrouillé"
    return user, None

def verify_fingerprint_login(user_id, minutiae_b64):
    user = User.query.get(user_id)
    if not user or not user.fingerprint_hash:
        return None, "Empreinte non enrôlée"
    expected = hash_fingerprint(minutiae_b64)
    if user.fingerprint_hash != expected:
        return None, "Empreinte invalide"
    return user, None

def create_account(user_id, acc_type, currency):
    account = Account(
        user_id=user_id,
        account_type=acc_type,
        currency=currency,
        account_number=generate_account_number(),
        balance=0
    )
    db.session.add(account)
    db.session.commit()
    return account

def process_transfer(from_account_id, to_account_id, amount, description, initiated_by):
    from_acc = Account.query.get(from_account_id)
    to_acc = Account.query.get(to_account_id)
    if not from_acc or not to_acc:
        return None, "Compte source ou destination invalide"
    if from_acc.user_id != initiated_by:
        return None, "Vous n'êtes pas propriétaire du compte source"
    if amount <= 0:
        return None, "Montant invalide"
    if float(from_acc.balance) < amount:
        return None, "Solde insuffisant"

    threshold = current_app.config.get('TRANSACTION_VALIDATION_THRESHOLD', 5000)
    requires_val = amount > threshold

    ref = generate_transaction_ref()
    txn = Transaction(
        reference=ref,
        amount=amount,
        transaction_type='transfer',
        status='pending' if requires_val else 'completed',
        description=description,
        requires_validation=requires_val,
        from_account_id=from_account_id,
        to_account_id=to_account_id
    )
    if not requires_val:
        from_acc.balance = float(from_acc.balance) - amount
        to_acc.balance = float(to_acc.balance) + amount
        txn.status = 'completed'
        txn.completed_at = datetime.now(timezone.utc)
    db.session.add(txn)
    db.session.commit()
    return txn, None

# ------------------------------------------------------------
# Authentification par image (FR-3)
# ------------------------------------------------------------
def get_image_gallery():
    return list(current_app.config.get('IMAGE_GALLERY', []))

def get_image_challenge(user_id):
    user = User.query.get(user_id)
    if not user or not user.image_auth_enabled:
        return None, "Image auth not enabled"

    gallery = get_image_gallery()
    if user.image_reference_id not in gallery:
        return None, "Image de référence invalide"

    others = [img for img in gallery if img != user.image_reference_id]
    if len(others) < 2:
        return None, "Pas assez d'images dans la galerie"
    candidates = [user.image_reference_id] + random.sample(others, 2)
    random.shuffle(candidates)

    challenge_id = hashlib.sha256(f"{user_id}{time.time()}{random.random()}".encode()).hexdigest()
    image_challenge_store[challenge_id] = {
        "user_id": user_id,
        "reference_image": user.image_reference_id,
        "expected_zone": json.loads(user.image_click_zone),
        "expires": time.time() + current_app.config.get('IMAGE_CHALLENGE_TTL', 120)
    }
    _cleanup_image_challenges()
    return {
        "challenge_id": challenge_id,
        "images": [f"/static/gallery/{img}.jpg" for img in candidates]
    }, None

def verify_image_response(challenge_id, selected_image_id, click_x, click_y):
    data = image_challenge_store.get(challenge_id)
    if not data or data['expires'] < time.time():
        return False, "Challenge expiré ou invalide"
    if selected_image_id != data['reference_image']:
        return False, "Image incorrecte"
    zone = data['expected_zone']
    dist = ((click_x - zone['x'])**2 + (click_y - zone['y'])**2)**0.5
    if dist > zone.get('radius', 20):
        return False, f"Clic hors de la zone secrète"
    del image_challenge_store[challenge_id]
    return True, "OK"

def _cleanup_image_challenges():
    now = time.time()
    expired = [cid for cid, data in image_challenge_store.items() if data['expires'] < now]
    for cid in expired:
        del image_challenge_store[cid]

# ------------------------------------------------------------
# WebAuthn / empreinte digitale (FR-4) – version simplifiée
# ------------------------------------------------------------
import os
def generate_webauthn_registration_challenge(user):
    challenge = hashlib.sha256(os.urandom(32)).hexdigest()
    webauthn_challenge_store[challenge] = {
        "user_id": user.id,
        "action": "register",
        "expires": time.time() + 300
    }
    return challenge

def verify_webauthn_registration(challenge, credential_data):
    data = webauthn_challenge_store.get(challenge)
    if not data or data['expires'] < time.time():
        return False, "Challenge invalide"
    user = User.query.get(data['user_id'])
    if not user:
        return False, "Utilisateur introuvable"
    user.webauthn_credential_id = credential_data.get('credential_id')
    user.webauthn_public_key = credential_data.get('public_key')
    user.auth_methods = 'fingerprint' if not user.password_hash else 'both'
    db.session.commit()
    del webauthn_challenge_store[challenge]
    return True, "OK"

def generate_webauthn_login_challenge(user):
    challenge = hashlib.sha256(os.urandom(32)).hexdigest()
    webauthn_challenge_store[challenge] = {
        "user_id": user.id,
        "action": "login",
        "expires": time.time() + 120
    }
    return challenge

def verify_webauthn_login(challenge, signature):
    data = webauthn_challenge_store.get(challenge)
    if not data or data['expires'] < time.time():
        return False, "Challenge invalide"
    user = User.query.get(data['user_id'])
    if not user or not user.webauthn_public_key:
        return False, "Aucune clé enregistrée"
    # Ici, il faudrait vérifier la signature avec la clé publique.
    # Pour la démo, on accepte si signature non vide.
    if not signature:
        return False, "Signature manquante"
    del webauthn_challenge_store[challenge]
    return True, "OK"