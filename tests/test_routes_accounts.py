def test_list_accounts_empty(client, auth_headers):
    resp = client.get('/api/v1/accounts', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json == []

def test_create_account(client, auth_headers, sample_user):
    resp = client.post('/api/v1/accounts', headers=auth_headers, json={
        'account_type': 'savings',
        'currency': 'USD'
    })
    assert resp.status_code == 201
    assert resp.json['account_type'] == 'savings'
    assert resp.json['currency'] == 'USD'

def test_get_account(client, auth_headers, sample_account):
    resp = client.get(f'/api/v1/accounts/{sample_account.id}', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json['id'] == sample_account.id

def test_get_account_not_found(client, auth_headers):
    resp = client.get('/api/v1/accounts/unknown-id', headers=auth_headers)
    assert resp.status_code == 404

def test_list_accounts_with_data(client, auth_headers, sample_account):
    resp = client.get('/api/v1/accounts', headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json) == 1
    assert resp.json[0]['account_number'] == sample_account.account_number
