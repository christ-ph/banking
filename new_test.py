"""
tests/test_deposit_withdraw.py
Tests unitaires & d'intégration pour les endpoints Dépôt et Retrait enrichis.

Couvre chaque nœud du CFG :
  - Dépôt  : N2→N3, N4→N5, N6→N7, N8→N9, N10→N11, N13→N14,
              N15→N16, N18→N19, N21→N22, N22, N23→N24(bonus)
  - Retrait : mêmes nœuds + N17(frais), N23→N24(frais séparés)
  - Helpers : _compute_withdrawal_fee, _compute_deposit_bonus, _get_today_volume
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def app():
    """Application Flask en mode test avec SQLite en mémoire."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    from flask import Flask
    from flask_jwt_extended import JWTManager
    flask_app = Flask(__name__)
    flask_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'JWT_SECRET_KEY': 'test-secret',
        'JWT_TOKEN_LOCATION': ['headers'],
        'JWT_HEADER_NAME': 'Authorization',
        'JWT_HEADER_TYPE': 'Bearer',
    })

    from models import db
    db.init_app(flask_app)
    JWTManager(flask_app)

    # Enregistrer seulement les routes dépôt/retrait enrichies
    from routes import api
    flask_app.register_blueprint(api, url_prefix='/api/v1')

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db_session(app):
    from models import db
    with app.app_context():
        yield db.session


@pytest.fixture
def user_and_token(app):
    """Crée un utilisateur, un compte XAF actif et retourne (user, account, jwt_token)."""
    from models import db, User, Account
    from flask_jwt_extended import create_access_token

    with app.app_context():
        user = User(
            id='user-001',
            email='test@bank.cm',
            password_hash='hashed',
            is_active=True,
            role='client'
        )
        db.session.add(user)
        db.session.flush()

        account = Account(
            id='acc-001',
            account_number='CM12345678901234567890123',
            account_type='current',
            balance=500_000,
            currency='XAF',
            is_active=True,
            user_id=user.id
        )
        db.session.add(account)
        db.session.commit()

        token = create_access_token(identity=user.id)
        yield user.id, account.id, token


def auth_headers(token):
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DES HELPERS
# ══════════════════════════════════════════════════════════════════════════════

class TestComputeWithdrawalFee:
    """Couvre for #2 — boucle sur les tranches de frais."""

    def test_gratuit_sous_100k(self, app):
        from routes import _compute_withdrawal_fee
        with app.app_context():
            assert _compute_withdrawal_fee(50_000, 'XAF') == 0.0

    def test_tranche_0_5_pct(self, app):
        from routes import _compute_withdrawal_fee
        with app.app_context():
            fee = _compute_withdrawal_fee(200_000, 'XAF')
            assert fee == pytest.approx(1_000.0)   # 200k × 0.5%

    def test_tranche_1_pct(self, app):
        from routes import _compute_withdrawal_fee
        with app.app_context():
            fee = _compute_withdrawal_fee(1_000_000, 'XAF')
            assert fee == pytest.approx(10_000.0)  # 1M × 1%

    def test_tranche_1_5_pct(self, app):
        from routes import _compute_withdrawal_fee
        with app.app_context():
            fee = _compute_withdrawal_fee(3_000_000, 'XAF')
            assert fee == pytest.approx(45_000.0)  # 3M × 1.5%

    def test_pas_de_frais_hors_xaf(self, app):
        from routes import _compute_withdrawal_fee
        with app.app_context():
            assert _compute_withdrawal_fee(500_000, 'EUR') == 0.0


class TestComputeDepositBonus:
    """Couvre for #3 — boucle sur les paliers bonus."""

    def test_pas_de_bonus_sous_1m(self, app):
        from routes import _compute_deposit_bonus
        with app.app_context():
            assert _compute_deposit_bonus(500_000, 'XAF') == 0.0

    def test_bonus_0_1_pct(self, app):
        from routes import _compute_deposit_bonus
        with app.app_context():
            bonus = _compute_deposit_bonus(2_000_000, 'XAF')
            assert bonus == pytest.approx(2_000.0)   # 2M × 0.1%

    def test_bonus_0_2_pct(self, app):
        from routes import _compute_deposit_bonus
        with app.app_context():
            bonus = _compute_deposit_bonus(10_000_000, 'XAF')
            assert bonus == pytest.approx(20_000.0)  # 10M × 0.2%

    def test_pas_de_bonus_hors_xaf(self, app):
        from routes import _compute_deposit_bonus
        with app.app_context():
            assert _compute_deposit_bonus(2_000_000, 'EUR') == 0.0


class TestGetTodayVolume:
    """Couvre for #1 — iteration sur les transactions du jour."""

    def test_volume_zero_sans_transactions(self, app, user_and_token):
        from routes import _get_today_volume
        user_id, account_id, _ = user_and_token
        with app.app_context():
            assert _get_today_volume(account_id, 'deposit') == 0.0
            assert _get_today_volume(account_id, 'withdrawal') == 0.0

    def test_cumul_plusieurs_depots(self, app, user_and_token):
        from routes import _get_today_volume
        from models import db, Transaction
        user_id, account_id, _ = user_and_token
        with app.app_context():
            for amount in [100_000, 200_000, 300_000]:
                db.session.add(Transaction(
                    reference=f'TXN-TEST-{amount}',
                    amount=amount, currency='XAF',
                    transaction_type='deposit', status='completed',
                    to_account_id=account_id,
                    created_at=datetime.now(timezone.utc)
                ))
            db.session.commit()
            total = _get_today_volume(account_id, 'deposit')
            assert total == 600_000.0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS ENDPOINT DÉPÔT
# ══════════════════════════════════════════════════════════════════════════════

class TestDeposit:

    # ── N2→N3 : account_id manquant ────────────────────────────────────────
    def test_n3_account_id_manquant(self, client, user_and_token):
        _, _, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'account_id' in r.get_json()['error']

    # ── N4→N5 : montant non numérique ─────────────────────────────────────
    def test_n5_montant_non_numerique(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 'abc'}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'invalide' in r.get_json()['error'].lower()

    # ── N6→N7 : montant négatif ────────────────────────────────────────────
    def test_n7_montant_negatif(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': -500}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'positif' in r.get_json()['error'].lower()

    # ── N6→N7 : montant zéro ──────────────────────────────────────────────
    def test_n7_montant_zero(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 0}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N8→N9 : compte inexistant ─────────────────────────────────────────
    def test_n9_compte_inexistant(self, client, user_and_token):
        _, _, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': 'acc-xxx', 'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 403

    # ── N10→N11 : compte désactivé ────────────────────────────────────────
    def test_n11_compte_desactive(self, client, app, user_and_token):
        from models import db, Account
        user_id, account_id, token = user_and_token
        with app.app_context():
            Account.query.filter_by(id=account_id).update({'is_active': False})
            db.session.commit()
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 403
        assert 'désactivé' in r.get_json()['error']

    # ── N13→N14 : montant sous minimum ────────────────────────────────────
    def test_n14_montant_sous_minimum(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 10}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'minimum' in r.get_json()['error'].lower()

    # ── N15→N16 : plafond par opération dépassé ───────────────────────────
    def test_n16_plafond_operation(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 6_000_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'plafond' in r.get_json()['error'].lower()

    # ── N18→N19 : plafond journalier dépassé ──────────────────────────────
    def test_n19_plafond_journalier(self, client, app, user_and_token):
        from models import db, Transaction
        _, account_id, token = user_and_token
        # Injecter des dépôts fictifs pour dépasser le plafond
        with app.app_context():
            for i in range(4):
                db.session.add(Transaction(
                    reference=f'TXN-CAP-{i}',
                    amount=4_900_000, currency='XAF',
                    transaction_type='deposit', status='completed',
                    to_account_id=account_id,
                    created_at=datetime.now(timezone.utc)
                ))
            db.session.commit()
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 1_000_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'journalier' in r.get_json()['error'].lower()

    # ── N20 : dépôt nominal sans bonus ────────────────────────────────────
    def test_n23_depot_simple_sans_bonus(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 50_000}),
                        headers=auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        assert data['bonus_applied'] == 0.0
        assert data['new_balance'] == 550_000.0

    # ── N21→N22 : bonus de fidélité appliqué ──────────────────────────────
    def test_n22_depot_avec_bonus(self, client, app, user_and_token):
        from models import db, Account
        user_id, account_id, token = user_and_token
        with app.app_context():
            Account.query.filter_by(id=account_id).update({'balance': 0})
            db.session.commit()
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 2_000_000}),
                        headers=auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        assert data['bonus_applied'] == pytest.approx(2_000.0)    # 0.1% de 2M
        assert data['effective_amount'] == pytest.approx(2_002_000.0)
        # new_balance = 0 (remis à zéro) + 2_002_000
        assert data['new_balance'] == pytest.approx(2_002_000.0)

    # ── Idempotence : deux dépôts successifs ──────────────────────────────
    def test_deux_depots_successifs(self, client, user_and_token):
        _, account_id, token = user_and_token
        payload = json.dumps({'account_id': account_id, 'amount': 100_000})
        r1 = client.post('/api/v1/transactions/deposit', data=payload, headers=auth_headers(token))
        r2 = client.post('/api/v1/transactions/deposit', data=payload, headers=auth_headers(token))
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r2.get_json()['new_balance'] == pytest.approx(700_000.0)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS ENDPOINT RETRAIT
# ══════════════════════════════════════════════════════════════════════════════

class TestWithdraw:

    # ── N2→N3 : account_id manquant ────────────────────────────────────────
    def test_n3_account_id_manquant(self, client, user_and_token):
        _, _, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N4→N5 : montant non numérique ─────────────────────────────────────
    def test_n5_montant_non_numerique(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 'xyz'}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N6→N7 : montant négatif ────────────────────────────────────────────
    def test_n7_montant_negatif(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': -1}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N8→N9 : compte inexistant ─────────────────────────────────────────
    def test_n9_compte_inexistant(self, client, user_and_token):
        _, _, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': 'acc-none', 'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 403

    # ── N10→N11 : compte désactivé ────────────────────────────────────────
    def test_n11_compte_desactive(self, client, app, user_and_token):
        from models import db, Account
        user_id, account_id, token = user_and_token
        with app.app_context():
            Account.query.filter_by(id=account_id).update({'is_active': False})
            db.session.commit()
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 10_000}),
                        headers=auth_headers(token))
        assert r.status_code == 403

    # ── N13→N14 : sous minimum ────────────────────────────────────────────
    def test_n14_montant_sous_minimum(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 5}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N15→N16 : plafond par opération ───────────────────────────────────
    def test_n16_plafond_operation(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 6_000_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N18→N19 : solde insuffisant (avec frais) ──────────────────────────
    def test_n19_solde_insuffisant(self, client, user_and_token):
        _, account_id, token = user_and_token
        # Solde = 500k, on demande 500k → total avec frais > 500k
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 500_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        data = r.get_json()
        assert 'fee' in data
        assert data['fee'] > 0

    # ── N19 : solde clairement insuffisant ────────────────────────────────
    def test_n19_solde_clairement_insuffisant(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 4_999_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400

    # ── N21→N22 : plafond journalier retrait ──────────────────────────────
    def test_n22_plafond_journalier_retrait(self, client, app, user_and_token):
        from models import db, Account, Transaction
        user_id, account_id, token = user_and_token
        with app.app_context():
            Account.query.filter_by(id=account_id).update({'balance': 100_000_000})
            db.session.commit()
            for i in range(4):
                db.session.add(Transaction(
                    reference=f'TXN-RET-D-{i}',
                    amount=4_900_000, currency='XAF',
                    transaction_type='withdrawal', status='completed',
                    from_account_id=account_id,
                    created_at=datetime.now(timezone.utc)
                ))
            db.session.commit()
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 1_000_000}),
                        headers=auth_headers(token))
        assert r.status_code == 400
        assert 'journalier' in r.get_json()['error'].lower()

    # ── N23 : retrait sans frais (< 100k XAF) ─────────────────────────────
    def test_n25_retrait_sans_frais(self, client, user_and_token):
        _, account_id, token = user_and_token
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 50_000}),
                        headers=auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        assert data['fee'] == 0.0
        assert 'fee_transaction' not in data
        assert data['new_balance'] == pytest.approx(450_000.0)

    # ── N24 : retrait avec frais (branche frais séparés) ──────────────────
    def test_n24_retrait_avec_frais(self, client, app, user_and_token):
        from models import db, Account
        user_id, account_id, token = user_and_token
        with app.app_context():
            Account.query.filter_by(id=account_id).update({'balance': 2_000_000})
            db.session.commit()
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 200_000}),
                        headers=auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        expected_fee = round(200_000 * 0.005, 2)   # 0.5% = 1000 XAF
        assert data['fee'] == pytest.approx(expected_fee)
        assert 'fee_transaction' in data
        assert data['total_debit'] == pytest.approx(200_000 + expected_fee)
        # new_balance = 2_000_000 - total_debit
        assert data['new_balance'] == pytest.approx(2_000_000 - 200_000 - expected_fee)

    # ── Cohérence balance après retrait ────────────────────────────────────
    def test_balance_coherente_apres_retrait(self, client, app, user_and_token):
        from models import db, Account
        user_id, account_id, token = user_and_token
        with app.app_context():
            acc = Account.query.get(account_id)
            balance_avant = float(acc.balance)

        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': account_id, 'amount': 50_000}),
                        headers=auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()

        with app.app_context():
            acc = Account.query.get(account_id)
            balance_apres = float(acc.balance)

        assert balance_apres == pytest.approx(balance_avant - data['total_debit'])


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DE SÉCURITÉ
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurity:

    def test_depot_sans_jwt(self, client):
        """Sans token JWT → 401."""
        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': 'acc-001', 'amount': 10_000}),
                        headers={'Content-Type': 'application/json'})
        assert r.status_code == 401

    def test_retrait_sans_jwt(self, client):
        r = client.post('/api/v1/transactions/withdraw',
                        data=json.dumps({'account_id': 'acc-001', 'amount': 10_000}),
                        headers={'Content-Type': 'application/json'})
        assert r.status_code == 401

    def test_depot_compte_autre_user(self, client, app, user_and_token):
        """Un utilisateur ne peut pas déposer sur le compte d'un autre."""
        from models import db, User, Account
        from flask_jwt_extended import create_access_token

        user_id, account_id, _ = user_and_token
        with app.app_context():
            other_user = User(
                id='user-002', email='other@bank.cm',
                password_hash='hashed', is_active=True
            )
            db.session.add(other_user)
            db.session.commit()
            other_token = create_access_token(identity='user-002')

        r = client.post('/api/v1/transactions/deposit',
                        data=json.dumps({'account_id': account_id, 'amount': 10_000}),
                        headers=auth_headers(other_token))
        assert r.status_code == 403