"""
Logique métier : authentification, comptes, transactions, image challenge, WebAuthn.

CORRECTIONS :
  1. verify_fingerprint_login : utilise check_fingerprint(bcrypt) au lieu de
     comparaison SHA-256 directe
  2. get_image_challenge / verify_image_response : le challenge_id retourné
     par verify_image_response était supprimé du store AVANT que routes.py
     puisse lire user_id — on retourne maintenant user_id directement dans
     le résultat de verify_image_response
  3. verify_webauthn_login : même correction, retourne user_id dans le tuple
  4. process_transfer : vérifie from_acc.user_id == initiated_by AVANT toute
     opération (sécurité)
"""
import json
import hashlib
import time
import random
import os
from flask import current_app
from datetime import datetime, timezone
from models import db, User, Account, Transaction
from utils import (
    verify_password, hash_fingerprint, check_fingerprint,
    log_action, generate_transaction_ref, generate_account_number
)

# Stores en mémoire (à remplacer par Redis en production)
image_challenge_store   = {}
webauthn_challenge_store = {}


# ── Authentification par mot de passe ─────────────────────────────────────────

def verify_login(email, password):
    if not email or not password:
        return None, "Identifiants invalides"
    user = User.query.filter_by(email=email).first()
    if not user or not user.password_hash:
        return None, "Identifiants invalides"
    if not user.is_active:
        return None, "Compte désactivé"
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return None, "Compte temporairement verrouillé"
    if not verify_password(password, user.password_hash):
        # Incrémenter les tentatives échouées
        user.failed_attempts = (user.failed_attempts or 0) + 1
        max_att = current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS', 5)
        if user.failed_attempts >= max_att:
            from datetime import timedelta
            lockout = current_app.config.get('ACCOUNT_LOCKOUT_MINUTES', 15)
            user.locked_until   = datetime.now(timezone.utc) + timedelta(minutes=lockout)
            user.failed_attempts = 0
        db.session.commit()
        return None, "Identifiants invalides"
    # Succès — reset
    user.failed_attempts = 0
    user.locked_until    = None
    db.session.commit()
    return user, None


# ── Authentification par empreinte (hash bcrypt) ───────────────────────────────

def verify_fingerprint_login(user_id, minutiae_b64):
    """
    CORRECTION : utilise check_fingerprint (bcrypt+pepper) au lieu de
    comparer deux hash SHA-256.
    """
    user = User.query.get(user_id)
    if not user or not user.fingerprint_hash:
        return None, "Empreinte non enrôlée"
    if not check_fingerprint(minutiae_b64, user.fingerprint_hash):
        return None, "Empreinte invalide"
    return user, None


# ── Comptes ───────────────────────────────────────────────────────────────────

def create_account(user_id, acc_type, currency):
    account = Account(
        user_id        = user_id,
        account_type   = acc_type,
        currency       = currency,
        account_number = generate_account_number(),
        balance        = 0
    )
    db.session.add(account)
    db.session.commit()
    return account


# ── Transactions ───────────────────────────────────────────────────────────────

def process_transfer(from_account_id, to_account_id, amount, description, initiated_by):
    from_acc = Account.query.get(from_account_id)
    to_acc   = Account.query.get(to_account_id)

    if not from_acc or not to_acc:
        return None, "Compte source ou destination invalide"
    if from_acc.user_id != initiated_by:
        return None, "Vous n'êtes pas propriétaire du compte source"
    if amount <= 0:
        return None, "Montant invalide"
    if float(from_acc.balance) < amount:
        return None, "Solde insuffisant"

    threshold    = current_app.config.get('TRANSACTION_VALIDATION_THRESHOLD', 10_000)
    requires_val = amount > threshold

    txn = Transaction(
        reference           = generate_transaction_ref(),
        amount              = amount,
        currency            = from_acc.currency,
        transaction_type    = 'transfer',
        status              = 'pending' if requires_val else 'completed',
        description         = description,
        requires_validation = requires_val,
        from_account_id     = from_account_id,
        to_account_id       = to_account_id
    )

    if not requires_val:
        from_acc.balance = float(from_acc.balance) - amount
        to_acc.balance   = float(to_acc.balance)   + amount
        txn.completed_at = datetime.now(timezone.utc)

    db.session.add(txn)
    db.session.commit()
    return txn, None


# ── Authentification par image (FR-3) ─────────────────────────────────────────

def _cleanup_image_challenges():
    now     = time.time()
    expired = [cid for cid, d in image_challenge_store.items() if d['expires'] < now]
    for cid in expired:
        del image_challenge_store[cid]


def get_image_gallery():
    return list(current_app.config.get('IMAGE_GALLERY', []))


def get_image_challenge(user_id):
    user = User.query.get(user_id)
    if not user or not user.image_auth_enabled:
        return None, "Authentification par image non activée"
    if not user.image_reference_id or not user.image_click_zone:
        return None, "Image de référence non configurée"

    gallery = get_image_gallery()
    if user.image_reference_id not in gallery:
        return None, "Image de référence invalide"

    others = [img for img in gallery if img != user.image_reference_id]
    if len(others) < 2:
        return None, "Pas assez d'images dans la galerie"

    candidates = [user.image_reference_id] + random.sample(others, 2)
    random.shuffle(candidates)

    challenge_id = hashlib.sha256(
        f"{user_id}{time.time()}{random.random()}".encode()
    ).hexdigest()

    image_challenge_store[challenge_id] = {
        "user_id":         user_id,
        "reference_image": user.image_reference_id,
        "expected_zone":   json.loads(user.image_click_zone),
        "expires":         time.time() + current_app.config.get('IMAGE_CHALLENGE_TTL', 120)
    }
    _cleanup_image_challenges()

    return {
        "challenge_id": challenge_id,
        "images":       [f"/static/gallery/{img}.jpg" for img in candidates]
    }, None


def verify_image_response(challenge_id, selected_image_id, click_x, click_y):
    """
    CORRECTION : retourne (ok, msg, user_id) au lieu de (ok, msg).
    Ainsi routes.py récupère user_id AVANT la suppression du challenge du store.
    """
    data = image_challenge_store.get(challenge_id)
    if not data:
        return False, "Challenge invalide", None
    if data['expires'] < time.time():
        del image_challenge_store[challenge_id]
        return False, "Challenge expiré", None

    user_id = data['user_id']

    if selected_image_id != data['reference_image']:
        del image_challenge_store[challenge_id]
        return False, "Image incorrecte", None

    zone = data['expected_zone']
    dist = ((click_x - zone['x']) ** 2 + (click_y - zone['y']) ** 2) ** 0.5
    if dist > zone.get('radius', 20):
        del image_challenge_store[challenge_id]
        return False, "Clic hors de la zone secrète", None

    del image_challenge_store[challenge_id]
    return True, "OK", user_id


# ── WebAuthn / empreinte (FR-4) ────────────────────────────────────────────────

def generate_webauthn_registration_challenge(user):
    challenge = hashlib.sha256(os.urandom(32)).hexdigest()
    webauthn_challenge_store[challenge] = {
        "user_id": user.id,
        "action":  "register",
        "expires": time.time() + 300
    }
    return challenge


def verify_webauthn_registration(challenge, credential_data):
    data = webauthn_challenge_store.get(challenge)
    if not data or data['expires'] < time.time():
        webauthn_challenge_store.pop(challenge, None)
        return False, "Challenge invalide ou expiré"
    user = User.query.get(data['user_id'])
    if not user:
        return False, "Utilisateur introuvable"
    user.webauthn_credential_id = credential_data.get('credential_id')
    user.webauthn_public_key    = credential_data.get('public_key')
    user.auth_methods = 'fingerprint' if not user.password_hash else 'both'
    db.session.commit()
    del webauthn_challenge_store[challenge]
    return True, "OK"


def generate_webauthn_login_challenge(user):
    challenge = hashlib.sha256(os.urandom(32)).hexdigest()
    webauthn_challenge_store[challenge] = {
        "user_id": user.id,
        "action":  "login",
        "expires": time.time() + 120
    }
    return challenge


def verify_webauthn_login(challenge, signature):
    """
    CORRECTION : retourne (ok, msg, user_id) pour que routes.py
    récupère user_id AVANT la suppression du challenge.
    """
    data = webauthn_challenge_store.get(challenge)
    if not data or data['expires'] < time.time():
        webauthn_challenge_store.pop(challenge, None)
        return False, "Challenge invalide ou expiré", None

    user    = User.query.get(data['user_id'])
    user_id = data['user_id']

    if not user or not user.webauthn_public_key:
        del webauthn_challenge_store[challenge]
        return False, "Aucune clé enregistrée", None
    if not signature:
        del webauthn_challenge_store[challenge]
        return False, "Signature manquante", None

    # TODO production : vérifier la signature ECDSA avec user.webauthn_public_key
    del webauthn_challenge_store[challenge]
    return True, "OK", user_id