def test_get_my_profile(client, auth_headers, sample_user):
    resp = client.get('/api/v1/users/me', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json['email'] == sample_user.email

def test_update_my_profile(client, auth_headers, sample_user):
    resp = client.put('/api/v1/users/me', headers=auth_headers, json={
        'first_name': 'Alicia',
        'phone': '+237612345678'
    })
    assert resp.status_code == 200
    assert resp.json['user']['first_name'] == 'Alicia'
    assert resp.json['user']['phone'] == '+237612345678'
