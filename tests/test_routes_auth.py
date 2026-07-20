def test_register_success(client, db_session):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'newuser@example.com',
        'password': 'StrongP@ss1',
        'first_name': 'New',
        'last_name': 'User'
    })
    assert resp.status_code == 201
    assert 'user_id' in resp.json

def test_register_weak_password(client):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'weak@example.com',
        'password': 'weak'
    })
    assert resp.status_code == 400
    assert 'caractères' in resp.json['error']

def test_register_duplicate_email(client, sample_user):
    resp = client.post('/api/v1/auth/register', json={
        'email': 'alice@example.com',
        'password': 'Another123!'
    })
    assert resp.status_code == 409
    assert 'déjà utilisé' in resp.json['error']

def test_login_success(client, sample_user):
    resp = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'Test1234!'
    })
    assert resp.status_code == 200
    assert 'access_token' in resp.json
    assert resp.json['user']['email'] == 'alice@example.com'

def test_login_invalid(client, sample_user):
    resp = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'wrong'
    })
    assert resp.status_code == 401
    assert resp.json['error'] == 'Identifiants invalides'

def test_refresh_token(client, sample_user):
    # D'abord login
    login = client.post('/api/v1/auth/login', json={
        'email': 'alice@example.com',
        'password': 'Test1234!'
    })
    refresh = login.json['refresh_token']
    resp = client.post('/api/v1/auth/refresh', headers={
        'Authorization': f'Bearer {refresh}'
    })
    assert resp.status_code == 200
    assert 'access_token' in resp.json

def test_image_enrollment(client, auth_headers, sample_user):
    resp = client.post('/api/v1/auth/image/enroll', headers=auth_headers, json={
        'image_id': 'landscape1',
        'click_zone': {'x': 150, 'y': 250, 'radius': 20}
    })
    assert resp.status_code == 200
    assert sample_user.image_auth_enabled is True

def test_image_login_flow(client, sample_user, db_session):
    # Préparer l'utilisateur avec image
    sample_user.image_auth_enabled = True
    sample_user.image_reference_id = 'landscape1'
    sample_user.image_click_zone = '{"x":100,"y":200,"radius":15}'
    db_session.commit()
    # Step1
    step1 = client.post('/api/v1/auth/login/image', json={'email': 'alice@example.com'})
    assert step1.status_code == 200
    challenge_id = step1.json['challenge_id']
    # Step2
    step2 = client.post('/api/v1/auth/login/image/verify', json={
        'challenge_id': challenge_id,
        'selected_image_id': 'landscape1',
        'click_x': 100,
        'click_y': 200
    })
    assert step2.status_code == 200
    assert 'access_token' in step2.json
