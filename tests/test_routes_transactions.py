def test_transfer_success(client, auth_headers, sample_account):
    # Créer un second compte pour la destination
    create_resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'current'
    })
    to_account_id = create_resp.json['id']
    resp = client.post('/api/v1/transactions/transfer', headers=auth_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_account_id,
        'amount': 50,
        'description': 'Test transfer'
    })
    assert resp.status_code == 201
    assert 'Virement effectué' in resp.json['message']

def test_transfer_insufficient_funds(client, auth_headers, sample_account):
    create_resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'current'
    })
    to_account_id = create_resp.json['id']
    resp = client.post('/api/v1/transactions/transfer', headers=auth_headers, json={
        'from_account_id': sample_account.id,
        'to_account_id': to_account_id,
        'amount': 5000,
        'description': 'Too high'
    })
    assert resp.status_code == 400
    assert 'Solde insuffisant' in resp.json['error']

def test_deposit(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/deposit', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 200,
        'description': 'Cash deposit'
    })
    assert resp.status_code == 200
    assert resp.json['new_balance'] == 1200.0
    assert resp.json['transaction']['transaction_type'] == 'deposit'

def test_withdraw(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 100,
        'description': 'ATM withdrawal'
    })
    assert resp.status_code == 200
    assert resp.json['new_balance'] == 900.0

def test_withdraw_insufficient(client, auth_headers, sample_account):
    resp = client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id,
        'amount': 2000
    })
    assert resp.status_code == 400
    assert 'Solde insuffisant' in resp.json['error']

def test_list_transactions(client, auth_headers, sample_account):
    # Faire quelques transactions
    client.post('/api/v1/transactions/deposit', headers=auth_headers, json={
        'account_id': sample_account.id, 'amount': 100
    })
    client.post('/api/v1/transactions/withdraw', headers=auth_headers, json={
        'account_id': sample_account.id, 'amount': 50
    })
    resp = client.get('/api/v1/transactions', headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json) >= 2
