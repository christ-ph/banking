"""
Tous les endpoints API du système bancaire.
Préfixe : /api/v1 (défini dans app.py)

CORRECTIONS :
  1. login_image_step2 : user_id lu depuis la valeur de retour de
     verify_image_response (3e élément du tuple) — plus de lecture du store
     après suppression
  2. login_password_image_step2 : même correction
  3. fingerprint_login_complete : user_id lu depuis verify_webauthn_login
  4. log_action appelé AVANT db.session.commit() (un seul commit par route)
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (jwt_required, create_access_token,
                                 create_refresh_token, get_jwt_identity)
from models import db, User, Account, Transaction, AuditLog
from services import (
    verify_login, verify_fingerprint_login,
    create_account, process_transfer,
    get_image_challenge, verify_image_response,
    generate_webauthn_registration_challenge, verify_webauthn_registration,
    generate_webauthn_login_challenge, verify_webauthn_login,
    image_challenge_store
)
from utils import (hash_password, hash_fingerprint, validate_password_strength,
                   admin_required, log_action)
import json

api = Blueprint('api', __name__)


# ══════════════════════════════════════════════════════════════════════════════
# AUTH CLASSIQUE
# ══════════════════════════════════════════════════════════════════════════════

@api.post('/auth/register')
def register():
    """
    Enregistrement d'un nouvel utilisateur
    ---
    tags: [Authentification]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [email, password]
          properties:
            email:       {type: string, example: "alice@example.com"}
            password:    {type: string, example: "StrongP@ss1"}
            first_name:  {type: string}
            last_name:   {type: string}
            phone:       {type: string}
    responses:
      201: {description: Compte créé}
      400: {description: Données invalides}
      409: {description: Email déjà utilisé}
    """
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"error": "email et password requis"}), 400

    valid, msg = validate_password_strength(password)
    if not valid:
        return jsonify({"error": msg}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email déjà utilisé"}), 409

    user = User(
        email         = email,
        password_hash = hash_password(password),
        first_name    = data.get('first_name', ''),
        last_name     = data.get('last_name', ''),
        phone         = data.get('phone', '')
    )
    db.session.add(user)
    db.session.flush()   # génère user.id sans commit
    log_action('user_registered', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({"message": "Compte créé", "user_id": user.id}), 201


@api.post('/auth/login')
def login():
    """
    Connexion par email / mot de passe
    ---
    tags: [Authentification]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [email, password]
          properties:
            email:    {type: string}
            password: {type: string}
    responses:
      200: {description: Connexion réussie}
      401: {description: Identifiants invalides}
    """
    data = request.get_json(silent=True) or {}
    user, error = verify_login(data.get('email', ''), data.get('password', ''))
    if error:
        return jsonify({"error": error}), 401

    access  = create_access_token(identity=user.id)
    refresh = create_refresh_token(identity=user.id)
    log_action('login_password', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "Bearer",
        "user":          user.to_dict()
    }), 200


@api.post('/auth/refresh')
@jwt_required(refresh=True)
def refresh_token():
    """
    Rafraîchir le token d'accès
    ---
    tags: [Authentification]
    security: [{Bearer: []}]
    responses:
      200: {description: Nouveau token}
      401: {description: Token invalide}
    """
    user_id = get_jwt_identity()
    access  = create_access_token(identity=user_id)
    return jsonify({"access_token": access}), 200


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTIFICATION PAR IMAGE (FR-3)
# ══════════════════════════════════════════════════════════════════════════════

@api.post('/auth/image/enroll')
@jwt_required()
def enroll_image():
    """
    Enrôlement de l'image de référence + zone cliquable
    ---
    tags: [Authentification par image]
    security: [{Bearer: []}]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [image_id, click_zone]
          properties:
            image_id:   {type: string, example: "landscape1"}
            click_zone:
              type: object
              properties:
                x:      {type: integer}
                y:      {type: integer}
                radius: {type: integer}
    responses:
      200: {description: Image et zone enregistrées}
      400: {description: Paramètres invalides}
      404: {description: Utilisateur introuvable}
    """
    data    = request.get_json(silent=True) or {}
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    image_id   = data.get('image_id')
    click_zone = data.get('click_zone')

    if not image_id or not click_zone:
        return jsonify({"error": "image_id et click_zone requis"}), 400

    gallery = current_app.config.get('IMAGE_GALLERY', set())
    if image_id not in gallery:
        return jsonify({"error": "Image invalide"}), 400

    if not isinstance(click_zone, dict) or 'x' not in click_zone or 'y' not in click_zone:
        return jsonify({"error": "Zone cliquable mal formatée (x et y requis)"}), 400

    user.image_reference_id = image_id
    user.image_click_zone   = json.dumps(click_zone)
    user.image_auth_enabled = True
    user.auth_methods       = 'both' if user.password_hash else 'image'
    log_action('image_enrolled', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({"message": "Image et zone secrète enregistrées"}), 200


@api.post('/auth/login/image')
def login_image_step1():
    """
    Étape 1 image : obtenir un challenge à partir de l'email
    ---
    tags: [Authentification par image]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [email]
          properties:
            email: {type: string}
    responses:
      200: {description: Challenge généré}
      401: {description: Image auth non activée}
    """
    data  = request.get_json(silent=True) or {}
    email = data.get('email')
    if not email:
        return jsonify({"error": "email requis"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.image_auth_enabled:
        return jsonify({"error": "Authentification par image non activée"}), 401

    challenge, err = get_image_challenge(user.id)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(challenge), 200


@api.post('/auth/login/image/verify')
def login_image_step2():
    """
    Étape 2 image : soumettre la réponse (image + coordonnées)
    ---
    tags: [Authentification par image]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [challenge_id, selected_image_id, click_x, click_y]
          properties:
            challenge_id:      {type: string}
            selected_image_id: {type: string}
            click_x:           {type: integer}
            click_y:           {type: integer}
    responses:
      200: {description: Authentification réussie}
      401: {description: Réponse invalide}
    """
    data              = request.get_json(silent=True) or {}
    challenge_id      = data.get('challenge_id')
    selected_image_id = data.get('selected_image_id')
    click_x           = data.get('click_x')
    click_y           = data.get('click_y')

    if not all([challenge_id, selected_image_id, click_x is not None, click_y is not None]):
        return jsonify({"error": "challenge_id, selected_image_id, click_x, click_y requis"}), 400

    # CORRECTION : verify_image_response retourne maintenant (ok, msg, user_id)
    ok, msg, user_id = verify_image_response(challenge_id, selected_image_id, click_x, click_y)
    if not ok:
        return jsonify({"error": msg}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    access  = create_access_token(identity=user.id)
    refresh = create_refresh_token(identity=user.id)
    log_action('login_image', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "Bearer"
    }), 200


@api.post('/auth/login/password-image')
def login_password_image_step1():
    """
    MFA étape 1 : mot de passe → challenge image
    ---
    tags: [Authentification par image]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [email, password]
          properties:
            email:    {type: string}
            password: {type: string}
    responses:
      200: {description: Challenge image généré}
      401: {description: Mot de passe invalide}
    """
    data        = request.get_json(silent=True) or {}
    user, error = verify_login(data.get('email'), data.get('password'))
    if error:
        return jsonify({"error": error}), 401
    if not user.image_auth_enabled:
        return jsonify({"error": "Authentification par image non activée"}), 400

    challenge, err = get_image_challenge(user.id)
    if err:
        return jsonify({"error": err}), 400

    # Stocker que le mot de passe a été vérifié pour ce challenge
    cid = challenge['challenge_id']
    if cid in image_challenge_store:
        image_challenge_store[cid]['password_verified_user'] = user.id

    return jsonify(challenge), 200


@api.post('/auth/login/password-image/verify')
def login_password_image_step2():
    """
    MFA étape 2 : réponse image → tokens
    ---
    tags: [Authentification par image]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [challenge_id, selected_image_id, click_x, click_y]
          properties:
            challenge_id:      {type: string}
            selected_image_id: {type: string}
            click_x:           {type: integer}
            click_y:           {type: integer}
    responses:
      200: {description: Double authentification réussie}
      401: {description: Réponse image invalide}
    """
    data              = request.get_json(silent=True) or {}
    challenge_id      = data.get('challenge_id')
    selected_image_id = data.get('selected_image_id')
    click_x           = data.get('click_x')
    click_y           = data.get('click_y')

    # Lire password_verified_user AVANT verify_image_response (qui supprime le challenge)
    stored = image_challenge_store.get(challenge_id, {})
    password_verified_user = stored.get('password_verified_user')

    ok, msg, _ = verify_image_response(challenge_id, selected_image_id, click_x, click_y)
    if not ok:
        return jsonify({"error": msg}), 401

    if not password_verified_user:
        return jsonify({"error": "Flux invalide : mot de passe non vérifié"}), 400

    user = User.query.get(password_verified_user)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    access  = create_access_token(identity=user.id)
    refresh = create_refresh_token(identity=user.id)
    log_action('login_password_image', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "Bearer"
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTIFICATION PAR EMPREINTE / WebAuthn (FR-4)
# ══════════════════════════════════════════════════════════════════════════════

@api.post('/auth/fingerprint/register/begin')
@jwt_required()
def fingerprint_register_begin():
    """
    Début enrôlement WebAuthn : génère un challenge
    ---
    tags: [Authentification par empreinte]
    security: [{Bearer: []}]
    responses:
      200: {description: Challenge généré}
      404: {description: Utilisateur introuvable}
    """
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    challenge = generate_webauthn_registration_challenge(user)
    return jsonify({"challenge": challenge}), 200


@api.post('/auth/fingerprint/register/complete')
@jwt_required()
def fingerprint_register_complete():
    """
    Fin enrôlement WebAuthn : enregistre la clé publique
    ---
    tags: [Authentification par empreinte]
    security: [{Bearer: []}]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [challenge, credential]
          properties:
            challenge:  {type: string}
            credential:
              type: object
              properties:
                credential_id: {type: string}
                public_key:    {type: string}
    responses:
      200: {description: Empreinte enrôlée}
      400: {description: Données invalides}
    """
    data            = request.get_json(silent=True) or {}
    challenge       = data.get('challenge')
    credential_data = data.get('credential')

    if not challenge or not credential_data:
        return jsonify({"error": "challenge et credential requis"}), 400

    ok, msg = verify_webauthn_registration(challenge, credential_data)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"message": "Empreinte digitale enrôlée avec succès"}), 200


@api.post('/auth/login/fingerprint/begin')
def fingerprint_login_begin():
    """
    Début auth empreinte : retourne un challenge
    ---
    tags: [Authentification par empreinte]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [email]
          properties:
            email: {type: string}
    responses:
      200: {description: Challenge généré}
      401: {description: Aucune empreinte enregistrée}
    """
    data  = request.get_json(silent=True) or {}
    email = data.get('email')
    if not email:
        return jsonify({"error": "email requis"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.webauthn_credential_id:
        return jsonify({"error": "Aucune empreinte enregistrée"}), 401

    challenge = generate_webauthn_login_challenge(user)
    return jsonify({
        "challenge":     challenge,
        "credential_id": user.webauthn_credential_id
    }), 200


@api.post('/auth/login/fingerprint/complete')
def fingerprint_login_complete():
    """
    Fin auth empreinte : vérifie la signature et retourne les tokens
    ---
    tags: [Authentification par empreinte]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [challenge, signature]
          properties:
            challenge:  {type: string}
            signature:  {type: string}
    responses:
      200: {description: Authentification réussie}
      401: {description: Signature invalide}
    """
    data      = request.get_json(silent=True) or {}
    challenge = data.get('challenge')
    signature = data.get('signature')

    if not challenge or not signature:
        return jsonify({"error": "challenge et signature requis"}), 400

    # CORRECTION : verify_webauthn_login retourne maintenant (ok, msg, user_id)
    ok, msg, user_id = verify_webauthn_login(challenge, signature)
    if not ok:
        return jsonify({"error": msg}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    access  = create_access_token(identity=user.id)
    refresh = create_refresh_token(identity=user.id)
    log_action('login_fingerprint', 'user', user.id, user.id)
    db.session.commit()
    return jsonify({
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "Bearer"
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
# COMPTES
# ══════════════════════════════════════════════════════════════════════════════

@api.get('/accounts')
@jwt_required()
def list_accounts():
    """
    Liste des comptes de l'utilisateur connecté
    ---
    tags: [Comptes]
    security: [{Bearer: []}]
    responses:
      200: {description: Liste des comptes}
    """
    user_id  = get_jwt_identity()
    accounts = Account.query.filter_by(user_id=user_id, is_active=True).all()
    return jsonify([a.to_dict() for a in accounts]), 200


@api.post('/accounts')
@jwt_required()
def open_account():
    """
    Ouvrir un nouveau compte
    ---
    tags: [Comptes]
    security: [{Bearer: []}]
    parameters:
      - name: body
        in: body
        schema:
          type: object
          properties:
            account_type: {type: string, enum: [current, savings, business], default: current}
            currency:     {type: string, default: XAF}
    responses:
      201: {description: Compte créé}
      400: {description: Type invalide}
    """
    data     = request.get_json(silent=True) or {}
    user_id  = get_jwt_identity()
    acc_type = data.get('account_type', 'current')
    currency = data.get('currency', 'XAF')

    if acc_type not in ('current', 'savings', 'business'):
        return jsonify({"error": "Type de compte invalide"}), 400

    account = create_account(user_id, acc_type, currency)
    return jsonify(account.to_dict()), 201


@api.get('/accounts/<account_id>')
@jwt_required()
def get_account(account_id):
    """
    Détail d'un compte
    ---
    tags: [Comptes]
    security: [{Bearer: []}]
    parameters:
      - name: account_id
        in: path
        type: string
        required: true
    responses:
      200: {description: Compte trouvé}
      404: {description: Introuvable}
    """
    user_id = get_jwt_identity()
    account = Account.query.filter_by(id=account_id, user_id=user_id).first()
    if not account:
        return jsonify({"error": "Compte introuvable"}), 404
    return jsonify(account.to_dict()), 200


# ══════════════════════════════════════════════════════════════════════════════
# TRANSACTIONS
# ══════════════════════════════════════════════════════════════════════════════

@api.post('/transactions/transfer')
@jwt_required()
def transfer():
    """
    Effectuer un virement
    ---
    tags: [Transactions]
    security: [{Bearer: []}]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [from_account_id, to_account_id, amount]
          properties:
            from_account_id: {type: string}
            to_account_id:   {type: string}
            amount:          {type: number}
            description:     {type: string}
    responses:
      201: {description: Virement effectué ou mis en attente}
      400: {description: Erreur}
    """
    data    = request.get_json(silent=True) or {}
    user_id = get_jwt_identity()
    try:
        amount = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Montant invalide"}), 400

    txn, error = process_transfer(
        from_account_id = data.get('from_account_id', ''),
        to_account_id   = data.get('to_account_id', ''),
        amount          = amount,
        description     = data.get('description', ''),
        initiated_by    = user_id
    )
    if error:
        return jsonify({"error": error}), 400

    msg = ("Virement effectué" if txn.status == 'completed'
           else "Virement en attente de validation (montant > seuil)")
    return jsonify({"message": msg, "transaction": txn.to_dict()}), 201


@api.get('/transactions')
@jwt_required()
def list_transactions():
    """
    Historique des 50 dernières transactions
    ---
    tags: [Transactions]
    security: [{Bearer: []}]
    responses:
      200: {description: Liste des transactions}
    """
    user_id  = get_jwt_identity()
    accounts = Account.query.filter_by(user_id=user_id).all()
    acc_ids  = [a.id for a in accounts]
    txns     = Transaction.query.filter(
        (Transaction.from_account_id.in_(acc_ids)) |
        (Transaction.to_account_id.in_(acc_ids))
    ).order_by(Transaction.created_at.desc()).limit(50).all()
    return jsonify([t.to_dict() for t in txns]), 200


# ══════════════════════════════════════════════════════════════════════════════
# ADMINISTRATION
# ══════════════════════════════════════════════════════════════════════════════

@api.get('/admin/users')
@jwt_required()
@admin_required
def admin_list_users():
    """
    Liste des utilisateurs (admin)
    ---
    tags: [Administration]
    security: [{Bearer: []}]
    responses:
      200: {description: Liste}
      403: {description: Accès refusé}
    """
    users = User.query.order_by(User.created_at.desc()).limit(100).all()
    return jsonify([u.to_dict() for u in users]), 200


@api.post('/admin/transactions/<txn_id>/validate')
@jwt_required()
@admin_required
def admin_validate_transaction(txn_id):
    """
    Valider une transaction en attente
    ---
    tags: [Administration]
    security: [{Bearer: []}]
    parameters:
      - name: txn_id
        in: path
        type: string
        required: true
    responses:
      200: {description: Transaction validée}
      400: {description: Déjà validée ou solde insuffisant}
      404: {description: Introuvable}
    """
    from datetime import datetime, timezone
    user_id = get_jwt_identity()
    txn     = Transaction.query.get(txn_id)
    if not txn:
        return jsonify({"error": "Transaction introuvable"}), 404
    if txn.status != 'pending':
        return jsonify({"error": f"Transaction déjà en état '{txn.status}'"}), 400

    from_acc = Account.query.get(txn.from_account_id)
    to_acc   = Account.query.get(txn.to_account_id)

    if float(from_acc.balance) < float(txn.amount):
        txn.status = 'failed'
        db.session.commit()
        return jsonify({"error": "Solde insuffisant au moment de la validation"}), 400

    from_acc.balance = float(from_acc.balance) - float(txn.amount)
    to_acc.balance   = float(to_acc.balance)   + float(txn.amount)
    txn.status       = 'completed'
    txn.validated_by = user_id
    txn.completed_at = datetime.now(timezone.utc)
    log_action('transaction_validated', 'transaction', txn.id, user_id)
    db.session.commit()
    return jsonify({"message": "Transaction validée", "transaction": txn.to_dict()}), 200


@api.get('/admin/audit')
@jwt_required()
@admin_required
def admin_audit_log():
    """
    Journal d'audit (admin)
    ---
    tags: [Administration]
    security: [{Bearer: []}]
    responses:
      200: {description: 200 derniers logs}
    """
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return jsonify([{
        'id':          l.id,
        'action':      l.action,
        'entity_type': l.entity_type,
        'entity_id':   l.entity_id,
        'ip_address':  l.ip_address,
        'user_id':     l.user_id,
        'created_at':  l.created_at.isoformat() if l.created_at else None
    } for l in logs]), 200


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@api.get('/health')
def health():
    """
    État du service
    ---
    tags: [Santé]
    responses:
      200: {description: OK}
    """
    return jsonify({"status": "ok", "service": "banking-api"}), 200