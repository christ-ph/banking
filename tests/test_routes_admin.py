def test_admin_list_users_as_admin(client, admin_headers):
    resp = client.get('/api/v1/admin/users', headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json, list)

def test_admin_list_users_as_non_admin(client, auth_headers):
    resp = client.get('/api/v1/admin/users', headers=auth_headers)
    assert resp.status_code == 403

def test_admin_create_user(client, admin_headers):
    resp = client.post('/api/v1/admin/users', headers=admin_headers, json={
        'email': 'newclient@example.com',
        'password': 'Client123!',
        'role': 'client'
    })
    assert resp.status_code == 201
    assert resp.json['user']['email'] == 'newclient@example.com'

def test_admin_update_user(client, admin_headers, sample_user):
    resp = client.put(f'/api/v1/admin/users/{sample_user.id}', headers=admin_headers, json={
        'role': 'operator',
        'is_active': False
    })
    assert resp.status_code == 200
    assert resp.json['user']['role'] == 'operator'
    assert resp.json['user']['is_active'] is False

def test_admin_delete_user(client, admin_headers, sample_user):
    # Créer un utilisateur spécifique pour suppression
    create = client.post('/api/v1/admin/users', headers=admin_headers, json={
        'email': 'todelete@example.com', 'password': 'Delete123!'
    })
    user_id = create.json['user']['id']
    resp = client.delete(f'/api/v1/admin/users/{user_id}', headers=admin_headers)
    assert resp.status_code == 200
    assert 'désactivé' in resp.json['message']

def test_admin_validate_transaction(client, admin_headers, sample_account, sample_user):
    # Créer une transaction en attente (montant > seuil)
    # D'abord créer un compte destinataire
    to_acc = client.post('/api/v1/accounts', headers=admin_headers, json={'account_type': 'current'})
    to_id = to_acc.json['id']
    transfer = client.post('/api/v1/transactions/transfer', headers=admin_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_id,
        'amount': 15000,
        'description': 'Big'
    })
    txn_id = transfer.json['transaction']['id']
    # Validation admin
    resp = client.post(f'/api/v1/admin/transactions/{txn_id}/validate', headers=admin_headers)
    assert resp.status_code == 200
    assert 'Transaction validée' in resp.json['message']

def test_admin_audit_log(client, admin_headers):
    resp = client.get('/api/v1/admin/audit', headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json, list)
