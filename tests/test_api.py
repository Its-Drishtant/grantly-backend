import os
import tempfile
from pathlib import Path

ROOT=Path(tempfile.mkdtemp(prefix='grantly-tests-'))
os.environ['DATABASE_URL']='sqlite:///'+str(ROOT/'test.db')
os.environ['UPLOAD_DIR']=str(ROOT/'uploads')
os.environ['JWT_SECRET']='test-only-key-not-for-production-1234567890'
from fastapi.testclient import TestClient
from app.main import app, eligibility, SessionLocal, User, select, attempts

def account(client, suffix):
    attempts.clear()
    r=client.post('/api/v1/auth/register',json={'name':'Test Student','email':f'{suffix}@example.com','password':'Correct-Horse-123!'})
    assert r.status_code==201,r.text
    return r.json()

def test_student_journey_and_ownership():
    with TestClient(app) as first, TestClient(app) as second:
        account(first,'one'); account(second,'two')
        assert first.get('/api/v1/admin/analytics').status_code==403
        listing=first.get('/api/v1/scholarships').json()['items']; sid=listing[0]['id']
        assert listing[0]['demo'] is True
        assert first.put('/api/v1/profile',json={'education_level':'Undergraduate','percentage':90,'income':100000,'state':'Karnataka','course':'Engineering','college':'Example'}).status_code==200
        assert first.get('/api/v1/profile').json()['completion']==100
        assert first.post('/api/v1/eligibility/check',json={'scholarship_id':sid}).json()['result']=='Eligible'
        assert first.get('/api/v1/recommendations').status_code==200
        assert first.post(f'/api/v1/saved/{sid}').status_code==200
        assert sid in first.get('/api/v1/saved').json()
        assert second.get('/api/v1/saved').json()==[]
        a=first.post('/api/v1/applications',json={'scholarship_id':sid}).json()
        update={'status':'Submitted','notes':'Applied externally','reference':'TEST-1','application_date':'2026-11-07'}
        assert second.put(f'/api/v1/applications/{a["id"]}',json=update).status_code==404
        assert first.put(f'/api/v1/applications/{a["id"]}',json=update).status_code==200
        assert len(first.get(f'/api/v1/applications/{a["id"]}/history').json())==2
        assert len(first.get('/api/v1/notifications').json())==2
        doc=first.post('/api/v1/documents/upload',files={'file':('test.pdf',b'%PDF-1.4\nDemo PDF','application/pdf')},data={'category':'Academic marksheet'})
        assert doc.status_code==201,doc.text
        did=doc.json()['id']
        assert second.get(f'/api/v1/documents/{did}/download').status_code==404
        assert first.get(f'/api/v1/documents/{did}/download').content.startswith(b'%PDF')
        assert first.post('/api/v1/documents/upload',files={'file':('bad.html',b'<script>alert(1)</script>','text/html')},data={'category':'Other'}).status_code==400
        assert first.delete(f'/api/v1/documents/{did}').status_code==200
        assert first.get('/api/v1/documents').json()==[]
        assert first.post('/api/v1/assistant',json={'question':'What documents?','scholarship_id':sid}).status_code==200
        assert first.put('/api/v1/preferences',json={'email':True,'in_app':True,'timezone':'Asia/Kolkata'}).status_code==200
        cookie=first.cookies.get('grantly_session')
        assert first.post('/api/v1/auth/logout').status_code==200
        first.cookies.set('grantly_session',cookie)
        assert first.get('/api/v1/profile').status_code==401

def test_eligibility_missing_and_failed():
    rules={'min_percentage':80,'max_income':200000,'education_level':'Undergraduate'}
    assert eligibility({},rules)['result']=='Possibly eligible'
    result=eligibility({'percentage':60},rules)
    assert result['result']=='Not eligible' and len(result['missing'])==2
    assert eligibility({'percentage':80,'income':200000,'education_level':'Undergraduate'},rules)['result']=='Eligible'

def test_account_tokens_and_csrf():
    with TestClient(app) as c:
        account(c,'tokens')
        r=c.post('/api/v1/auth/forgot-password',json={'email':'tokens@example.com'}).json()
        token=r['development_link'].split('token=')[1]
        assert c.post('/api/v1/auth/reset-password',json={'token':token,'password':'New-Password-123!'}).status_code==200
        assert c.post('/api/v1/auth/reset-password',json={'token':token,'password':'Again-Password-123!'}).status_code==400
        assert c.get('/api/v1/auth/me').status_code==401
        assert c.post('/api/v1/auth/login',json={'email':'tokens@example.com','password':'New-Password-123!'}).status_code==200
        assert c.put('/api/v1/profile',headers={'origin':'https://evil.example'},json={}).status_code==403

def test_admin_verification():
    with TestClient(app) as c:
        u=account(c,'admin')
        with SessionLocal() as db:
            user=db.get(User,u['id']); user.role='admin'; db.commit()
        assert c.get('/api/v1/admin/analytics').status_code==200
        assert c.post('/api/v1/admin/scholarships/1/verify').status_code==400
        assert c.get('/api/v1/admin/users').status_code==200
        payload={'name':'Test opportunity','provider':'Test provider','amount':1000,'category':'Private','level':'Undergraduate','deadline':'2027-01-01','description':'Test scholarship description','source_url':'https://example.com/scholarship'}
        created=c.post('/api/v1/admin/scholarships',json=payload)
        assert created.status_code==201,created.text
        assert c.post(f'/api/v1/admin/scholarships/{created.json()["id"]}/verify').status_code==200
