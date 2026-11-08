"""Grantly API. All private resources are scoped to the authenticated account."""
import hashlib
import os
import secrets
import smtplib
import time
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Literal

import jwt
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from . import storage
from pwdlib import PasswordHash
from sqlalchemy import create_engine, String, ForeignKey, UniqueConstraint, select, func, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./grantly.db')
engine = create_engine(DATABASE_URL, **({'connect_args': {'check_same_thread': False}} if DATABASE_URL.startswith('sqlite') else {}))
SessionLocal = sessionmaker(engine, expire_on_commit=False)
PRODUCTION = os.getenv('ENVIRONMENT') == 'production'
SECRET = os.getenv('JWT_SECRET') or secrets.token_hex(32)
if PRODUCTION and not os.getenv('JWT_SECRET'):
    raise RuntimeError('JWT_SECRET is required in production')
ORIGIN = os.getenv('FRONTEND_URL', 'http://localhost:3000')
UPLOADS = Path(os.getenv('UPLOAD_DIR', './private_uploads')).resolve()
UPLOADS.mkdir(exist_ok=True, parents=True)
passwords = PasswordHash.recommended()

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    name: Mapped[str]
    password: Mapped[str]
    role: Mapped[str] = mapped_column(default='student')
    verified: Mapped[bool] = mapped_column(default=False)
    active: Mapped[bool] = mapped_column(default=True)
    session_version: Mapped[int] = mapped_column(default=0)
class Profile(Base):
    __tablename__ = 'student_profiles'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
class Scholarship(Base):
    __tablename__ = 'scholarships'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    provider: Mapped[str]
    amount: Mapped[int]
    category: Mapped[str]
    level: Mapped[str]
    deadline: Mapped[str] = mapped_column(index=True)
    description: Mapped[str]
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    documents: Mapped[list] = mapped_column(JSON, default=list)
    source_url: Mapped[str] = mapped_column(default='')
    verification: Mapped[str] = mapped_column(default='Unverified')
    verified_at: Mapped[str | None]
    demo: Mapped[bool] = mapped_column(default=False)
    archived: Mapped[bool] = mapped_column(default=False)
class Saved(Base):
    __tablename__ = 'saved_scholarships'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    scholarship_id: Mapped[int] = mapped_column(ForeignKey('scholarships.id'), primary_key=True)
class Application(Base):
    __tablename__ = 'applications'
    __table_args__ = (UniqueConstraint('user_id','scholarship_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    scholarship_id: Mapped[int] = mapped_column(ForeignKey('scholarships.id'))
    status: Mapped[str] = mapped_column(default='Planning to Apply')
    notes: Mapped[str] = mapped_column(default='')
    reference: Mapped[str] = mapped_column(default='')
    application_date: Mapped[str] = mapped_column(default='')
    updated_at: Mapped[str] = mapped_column(default=lambda: datetime.now(timezone.utc).isoformat())
    archived: Mapped[bool] = mapped_column(default=False)
class History(Base):
    __tablename__ = 'application_status_history'
    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey('applications.id'), index=True)
    status: Mapped[str]
    timestamp: Mapped[str] = mapped_column(default=lambda: datetime.now(timezone.utc).isoformat())
class Document(Base):
    __tablename__ = 'student_documents'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    name: Mapped[str]
    key: Mapped[str]
    category: Mapped[str]
    size: Mapped[int]
    mime: Mapped[str]
    expiry: Mapped[str] = mapped_column(default='')
class Notification(Base):
    __tablename__ = 'notifications'
    __table_args__ = (UniqueConstraint('user_id','dedupe'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    title: Mapped[str]
    body: Mapped[str]
    read: Mapped[bool] = mapped_column(default=False)
    dedupe: Mapped[str]
    created_at: Mapped[str] = mapped_column(default=lambda: datetime.now(timezone.utc).isoformat())
class Preferences(Base):
    __tablename__ = 'reminder_preferences'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    email: Mapped[bool] = mapped_column(default=False)
    in_app: Mapped[bool] = mapped_column(default=True)
    timezone: Mapped[str] = mapped_column(default='Asia/Kolkata')
class Token(Base):
    __tablename__ = 'auth_tokens'
    digest: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    purpose: Mapped[str]
    expires: Mapped[float]
class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str]
    created_at: Mapped[str] = mapped_column(default=lambda: datetime.now(timezone.utc).isoformat())

def db():
    with SessionLocal() as session: yield session
def serialize(obj):
    return {c.name:getattr(obj,c.name) for c in obj.__table__.columns if c.name not in ('password','key','session_version')}
def current(request: Request, db: Session = Depends(db)):
    try:
        token = jwt.decode(request.cookies.get('grantly_session',''), SECRET, algorithms=['HS256'])
        user = db.get(User,int(token['sub']))
        if not user or not user.active or token['v'] != user.session_version: raise ValueError()
        return user
    except (jwt.PyJWTError, ValueError, KeyError): raise HTTPException(401,'Please sign in to continue')
def admin(user: User = Depends(current)):
    if user.role not in ('admin','super_admin'): raise HTTPException(403,'Administrator access required')
    return user
def own(db, model, ident, user):
    item=db.get(model,ident)
    if not item or item.user_id != user.id: raise HTTPException(404,'Not found')
    return item
def scholarship(db, ident):
    item=db.get(Scholarship,ident)
    if not item or item.archived: raise HTTPException(404,'Scholarship not found')
    return item

app = FastAPI(title='Grantly',version='1.0.0')
attempts = defaultdict(list)
@app.middleware('http')
async def security(request: Request, call_next):
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin=request.headers.get('origin')
        allowed={ORIGIN}
        if not PRODUCTION: allowed.update({'http://localhost:3000','http://127.0.0.1:3000'})
        if origin and origin not in allowed:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail':'Origin rejected'},status_code=403)
    if request.url.path.startswith('/api/v1/auth') and request.method=='POST':
        key=request.client.host if request.client else 'unknown'
        now=time.time(); attempts[key]=[t for t in attempts[key] if now-t<60]
        if len(attempts[key])>=20:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail':'Too many attempts. Try again in a minute.'},status_code=429)
        attempts[key].append(now)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Cache-Control']='no-store'
    return response

def seed(db):
    if db.scalar(select(func.count()).select_from(Scholarship)): return
    names=[('The Next Chapter Scholarship','Grantly Demo Foundation',75000,'Merit-based','Undergraduate',80,400000),('Bright Futures Education Grant','Demo Education Trust',50000,'Need-based','Undergraduate',60,250000),('Women in STEM Fellowship','Demo Science Collective',100000,'Research','Postgraduate',75,600000),('Open Horizons Scholarship','Demo Learning Fund',35000,'Private','Undergraduate',65,500000),('The Graduate Research Award','Demo Research Society',150000,'Research','Postgraduate',85,800000),('Community Scholars Programme','Demo Community Trust',25000,'Need-based','Undergraduate',55,300000)]
    for i,(name,provider,amount,category,level,marks,income) in enumerate(names):
        db.add(Scholarship(name=name,provider=provider,amount=amount,category=category,level=level,deadline=(date.today()+timedelta(days=[8,18,32,45,60,75][i])).isoformat(),description='A demonstration opportunity designed to help you explore the complete scholarship journey. This is not a real scholarship or an open application call.',rules={'education_level':level,'min_percentage':marks,'max_income':income},documents=['Academic marksheet','Income certificate','Admission proof'],demo=True,verification='Unverified'))
    db.commit()

@app.on_event('startup')
def startup():
    if not PRODUCTION:
        Base.metadata.create_all(engine)
        with SessionLocal() as session: seed(session)

class Register(BaseModel):
    name: str = Field(min_length=2,max_length=100)
    email: EmailStr
    password: str = Field(min_length=10,max_length=128)
class Login(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)
class EmailInput(BaseModel): email: EmailStr
class Reset(BaseModel):
    token: str
    password: str = Field(min_length=10,max_length=128)
def mail(address,subject,body):
    if not os.getenv('SMTP_HOST'): return False
    message=EmailMessage(); message['To']=address; message['From']=os.getenv('SMTP_FROM','hello@grantly.local'); message['Subject']=subject; message.set_content(body)
    with smtplib.SMTP(os.environ['SMTP_HOST'],int(os.getenv('SMTP_PORT','587')),timeout=15) as server:
        server.starttls()
        if os.getenv('SMTP_USER'): server.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
        server.send_message(message)
    return True
def issue_token(db,user,purpose):
    raw=secrets.token_urlsafe(40)
    db.add(Token(digest=hashlib.sha256(raw.encode()).hexdigest(),user_id=user.id,purpose=purpose,expires=time.time()+3600)); db.commit()
    url=f'{ORIGIN}/{"verify-email" if purpose=="verify" else "reset-password"}?token={raw}'
    sent=mail(user.email,'Your Grantly account',f'Open this link within one hour: {url}')
    return {'message':'Check your email for the next step.','development_link':url if not sent and not PRODUCTION else None}
def set_session(response,user):
    token=jwt.encode({'sub':str(user.id),'v':user.session_version,'exp':datetime.now(timezone.utc)+timedelta(hours=12)},SECRET,algorithm='HS256')
    response.set_cookie('grantly_session',token,httponly=True,secure=PRODUCTION,samesite='lax',max_age=43200,path='/')
@app.post('/api/v1/auth/register',status_code=201)
def register(data:Register,response:Response,db:Session=Depends(db)):
    email=str(data.email).lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,'An account with this email already exists')
    user=User(email=email,name=data.name,password=passwords.hash(data.password)); db.add(user); db.flush()
    db.add(Profile(user_id=user.id,data={})); db.add(Preferences(user_id=user.id)); db.add(Notification(user_id=user.id,title='Welcome to your next chapter',body='Complete your profile to get useful scholarship matches.',dedupe='welcome')); db.commit()
    set_session(response,user)
    return {**serialize(user),**issue_token(db,user,'verify')}
@app.post('/api/v1/auth/login')
def login(data:Login,response:Response,db:Session=Depends(db)):
    user=db.scalar(select(User).where(User.email==str(data.email).lower()))
    if not user or not user.active or not passwords.verify(data.password,user.password): raise HTTPException(401,'Incorrect email or password')
    set_session(response,user); return serialize(user)
@app.get('/api/v1/auth/me')
def me(user:User=Depends(current)): return serialize(user)
@app.post('/api/v1/auth/logout')
def logout(response:Response,user:User=Depends(current),db:Session=Depends(db)):
    user.session_version+=1; db.commit(); response.delete_cookie('grantly_session',path='/'); return {'ok':True}
@app.post('/api/v1/auth/forgot-password')
def forgot(data:EmailInput,db:Session=Depends(db)):
    user=db.scalar(select(User).where(User.email==str(data.email).lower()))
    if user: return issue_token(db,user,'reset')
    return {'message':'If an account exists, a reset link has been sent.'}
def consume(db,raw,purpose):
    item=db.get(Token,hashlib.sha256(raw.encode()).hexdigest())
    if not item or item.purpose!=purpose or item.expires<time.time(): raise HTTPException(400,'Invalid or expired link')
    user=db.get(User,item.user_id); db.delete(item); return user
@app.post('/api/v1/auth/reset-password')
def reset(data:Reset,db:Session=Depends(db)):
    user=consume(db,data.token,'reset'); user.password=passwords.hash(data.password); user.session_version+=1; db.commit(); return {'message':'Password updated. You can now sign in.'}
@app.post('/api/v1/auth/verify-email')
def verify(data:dict,db:Session=Depends(db)):
    user=consume(db,str(data.get('token','')),'verify'); user.verified=True; db.commit(); return {'message':'Email verified.'}

class ProfileInput(BaseModel):
    phone: str = Field(default='',max_length=30)
    date_of_birth: str = ''
    state: str = Field(default='',max_length=100)
    district: str = Field(default='',max_length=100)
    education_level: str = ''
    college: str = Field(default='',max_length=200)
    university: str = Field(default='',max_length=200)
    course: str = Field(default='',max_length=100)
    year: str = ''
    percentage: float | None = Field(default=None,ge=0,le=100)
    income: float | None = Field(default=None,ge=0)
    category: str = ''
    domicile: str = ''
    disability: str = ''
    income_certificate: bool = False
def completion(data):
    keys=['state','education_level','college','course','percentage','income']
    return round(sum(data.get(k) is not None and data.get(k)!='' for k in keys)/len(keys)*100)
@app.get('/api/v1/profile')
def profile(user:User=Depends(current),db:Session=Depends(db)):
    p=db.get(Profile,user.id); return {'data':p.data,'completion':completion(p.data)}
@app.put('/api/v1/profile')
def update_profile(data:ProfileInput,user:User=Depends(current),db:Session=Depends(db)):
    p=db.get(Profile,user.id); p.data=data.model_dump(); db.commit(); return {'data':p.data,'completion':completion(p.data)}

def eligibility(profile,rules):
    met=[]; missing=[]; failed=[]
    for key,required in rules.items():
        field={'min_percentage':'percentage','max_income':'income'}.get(key,key)
        value=profile.get(field)
        label=f'{field.replace("_"," ").title()}: {"at least " if key=="min_percentage" else "at most " if key=="max_income" else ""}{required}'
        if value is None or value=='': missing.append(label); continue
        ok=value>=required if key=='min_percentage' else value<=required if key=='max_income' else value in required if isinstance(required,list) else str(value).casefold()==str(required).casefold()
        (met if ok else failed).append(label)
    return {'result':'Not eligible' if failed else 'Possibly eligible' if missing else 'Eligible','met':met,'missing':missing,'failed':failed,'score':round(100*len(met)/max(len(rules),1)),'disclaimer':'Matching is guidance. The provider makes the final eligibility decision.'}
@app.get('/api/v1/scholarships')
def scholarships(q:str='',category:str='',level:str='',status:str='',sort:str='deadline',page:int=1,page_size:int=12,db:Session=Depends(db)):
    query=select(Scholarship).where(Scholarship.archived==False)
    if q: query=query.where((Scholarship.name.ilike(f'%{q}%')) | (Scholarship.provider.ilike(f'%{q}%')))
    if category: query=query.where(Scholarship.category==category)
    if level: query=query.where(Scholarship.level==level)
    if status=='open': query=query.where(Scholarship.deadline>=date.today().isoformat())
    if status=='closed': query=query.where(Scholarship.deadline<date.today().isoformat())
    count=db.scalar(select(func.count()).select_from(query.subquery()))
    query=query.order_by(Scholarship.amount.desc() if sort=='amount' else Scholarship.id.desc() if sort=='newest' else Scholarship.deadline)
    return {'items':[serialize(s) for s in db.scalars(query.offset((max(page,1)-1)*min(max(page_size,1),50)).limit(min(max(page_size,1),50)))],'total':count}
@app.get('/api/v1/scholarships/{ident}')
def detail(ident:int,db:Session=Depends(db)): return serialize(scholarship(db,ident))
@app.get('/api/v1/recommendations')
def recommendations(user:User=Depends(current),db:Session=Depends(db)):
    p=db.get(Profile,user.id).data
    items=[{**serialize(s),'eligibility':eligibility(p,s.rules)} for s in db.scalars(select(Scholarship).where(Scholarship.archived==False,Scholarship.deadline>=date.today().isoformat()))]
    return sorted(items,key=lambda x:(x['eligibility']['result']=='Not eligible',x['verification']!='Verified',-x['eligibility']['score'],x['deadline']))
class EligibilityInput(BaseModel): scholarship_id:int
@app.post('/api/v1/eligibility/check')
def check(data:EligibilityInput,user:User=Depends(current),db:Session=Depends(db)):
    return eligibility(db.get(Profile,user.id).data,scholarship(db,data.scholarship_id).rules)
@app.get('/api/v1/saved')
def saved(user:User=Depends(current),db:Session=Depends(db)):
    return [s.scholarship_id for s in db.scalars(select(Saved).where(Saved.user_id==user.id))]
@app.post('/api/v1/saved/{ident}')
def save(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    scholarship(db,ident); item=db.get(Saved,(user.id,ident))
    if not item: db.add(Saved(user_id=user.id,scholarship_id=ident)); db.commit()
    return {'saved':True}
@app.delete('/api/v1/saved/{ident}')
def unsave(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    item=db.get(Saved,(user.id,ident))
    if item: db.delete(item); db.commit()
    return {'saved':False}
STATUSES=['Interested','Planning to Apply','Application Started','Documents Pending','Ready to Submit','Submitted','Under Review','Additional Information Required','Approved','Rejected','On Hold']
class ApplicationInput(BaseModel): scholarship_id:int
class ApplicationUpdate(BaseModel):
    status: Literal['Interested','Planning to Apply','Application Started','Documents Pending','Ready to Submit','Submitted','Under Review','Additional Information Required','Approved','Rejected','On Hold']
    notes:str=Field(default='',max_length=10000)
    reference:str=Field(default='',max_length=200)
    application_date:str=''
    archived:bool=False
@app.get('/api/v1/applications')
def applications(user:User=Depends(current),db:Session=Depends(db)):
    return [{**serialize(a),'scholarship':serialize(db.get(Scholarship,a.scholarship_id))} for a in db.scalars(select(Application).where(Application.user_id==user.id).order_by(Application.id.desc()))]
@app.post('/api/v1/applications',status_code=201)
def create_application(data:ApplicationInput,user:User=Depends(current),db:Session=Depends(db)):
    scholarship(db,data.scholarship_id)
    old=db.scalar(select(Application).where(Application.user_id==user.id,Application.scholarship_id==data.scholarship_id))
    if old: return serialize(old)
    a=Application(user_id=user.id,scholarship_id=data.scholarship_id); db.add(a); db.flush(); db.add(History(application_id=a.id,status=a.status)); db.commit(); return serialize(a)
@app.put('/api/v1/applications/{ident}')
def update_application(ident:int,data:ApplicationUpdate,user:User=Depends(current),db:Session=Depends(db)):
    a=own(db,Application,ident,user)
    if a.status!=data.status:
        db.add(History(application_id=a.id,status=data.status))
        db.add(Notification(user_id=user.id,title='Application updated',body=f'You marked your application as {data.status}.',dedupe=secrets.token_hex(16)))
    for k,v in data.model_dump().items(): setattr(a,k,v)
    a.updated_at=datetime.now(timezone.utc).isoformat(); db.commit(); return serialize(a)
@app.get('/api/v1/applications/{ident}/history')
def history(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    own(db,Application,ident,user); return [serialize(h) for h in db.scalars(select(History).where(History.application_id==ident).order_by(History.id))]

@app.get('/api/v1/documents')
def documents(user:User=Depends(current),db:Session=Depends(db)):
    return [serialize(d) for d in db.scalars(select(Document).where(Document.user_id==user.id))]
@app.post('/api/v1/documents/upload',status_code=201)
async def upload(file:UploadFile=File(...),category:str=Form(...),expiry:str=Form(''),user:User=Depends(current),db:Session=Depends(db)):
    content=await file.read(10*1024*1024+1)
    if len(content)>10*1024*1024: raise HTTPException(413,'Maximum file size is 10 MB')
    mime='application/pdf' if content.startswith(b'%PDF-') else 'image/png' if content.startswith(b'\x89PNG\r\n\x1a\n') else 'image/jpeg' if content.startswith(b'\xff\xd8\xff') else None
    if not mime: raise HTTPException(400,'Upload a valid PDF, PNG or JPEG')
    if expiry:
        try: date.fromisoformat(expiry)
        except ValueError: raise HTTPException(422,'Invalid expiry date')
    key=secrets.token_hex(32); storage.put(key,content,mime,UPLOADS)
    d=Document(user_id=user.id,name=(file.filename or 'Document')[:200],key=key,category=category[:100],size=len(content),mime=mime,expiry=expiry); db.add(d); db.commit(); return serialize(d)
@app.get('/api/v1/documents/{ident}/download')
def download(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    d=own(db,Document,ident,user)
    if storage.configured(): return RedirectResponse(storage.signed_download(d.key,d.name))
    return FileResponse(UPLOADS/d.key,filename=d.name,media_type=d.mime)
@app.delete('/api/v1/documents/{ident}')
def delete_document(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    d=own(db,Document,ident,user); storage.delete(d.key,UPLOADS); db.delete(d); db.commit(); return {'ok':True}
@app.get('/api/v1/notifications')
def notifications(user:User=Depends(current),db:Session=Depends(db)):
    return [serialize(n) for n in db.scalars(select(Notification).where(Notification.user_id==user.id).order_by(Notification.id.desc()).limit(100))]
@app.put('/api/v1/notifications/{ident}/read')
def mark_read(ident:int,user:User=Depends(current),db:Session=Depends(db)):
    n=own(db,Notification,ident,user); n.read=True; db.commit(); return {'ok':True}
class PreferenceInput(BaseModel):
    email:bool=False
    in_app:bool=True
    timezone:str='Asia/Kolkata'
@app.get('/api/v1/preferences')
def preferences(user:User=Depends(current),db:Session=Depends(db)): return serialize(db.get(Preferences,user.id))
@app.put('/api/v1/preferences')
def update_preferences(data:PreferenceInput,user:User=Depends(current),db:Session=Depends(db)):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try: ZoneInfo(data.timezone)
    except ZoneInfoNotFoundError: raise HTTPException(422,'Unknown timezone')
    p=db.get(Preferences,user.id)
    for k,v in data.model_dump().items(): setattr(p,k,v)
    db.commit(); return serialize(p)

class ScholarshipInput(BaseModel):
    name:str=Field(min_length=3,max_length=200)
    provider:str=Field(min_length=2,max_length=200)
    amount:int=Field(ge=0)
    category:str
    level:str
    deadline:date
    description:str=Field(min_length=10,max_length=10000)
    rules:dict=Field(default_factory=dict)
    documents:list[str]=Field(default_factory=list)
    source_url:str=''
    demo:bool=False
    archived:bool=False
    @field_validator('rules')
    @classmethod
    def validate_rules(cls, rules):
        allowed={'min_percentage','max_income','education_level','state','course','category','domicile','disability','income_certificate'}
        for key,value in rules.items():
            if key not in allowed: raise ValueError(f'Unsupported eligibility field: {key}')
            if key in ('min_percentage','max_income'):
                if not isinstance(value,(int,float)) or isinstance(value,bool) or value<0: raise ValueError('Thresholds must be nonnegative numbers')
                if key=='min_percentage' and value>100: raise ValueError('Percentage cannot exceed 100')
            elif not isinstance(value,(str,bool,list)): raise ValueError('Requirements must be a string, boolean or list')
        return rules
    @field_validator('source_url')
    @classmethod
    def validate_source(cls, value):
        from urllib.parse import urlparse
        if value and (urlparse(value).scheme!='https' or not urlparse(value).netloc): raise ValueError('Use an HTTPS source URL')
        return value
@app.get('/api/v1/admin/analytics')
def analytics(user:User=Depends(admin),db:Session=Depends(db)):
    return {'students':db.scalar(select(func.count()).select_from(User).where(User.role=='student')),'scholarships':db.scalar(select(func.count()).select_from(Scholarship)),'applications':db.scalar(select(func.count()).select_from(Application)),'verified':db.scalar(select(func.count()).select_from(Scholarship).where(Scholarship.verification=='Verified'))}
@app.get('/api/v1/admin/users')
def users(user:User=Depends(admin),db:Session=Depends(db)): return [serialize(u) for u in db.scalars(select(User).limit(200))]
@app.post('/api/v1/admin/scholarships',status_code=201)
def add_scholarship(data:ScholarshipInput,user:User=Depends(admin),db:Session=Depends(db)):
    s=Scholarship(**data.model_dump(mode='json')); db.add(s); db.add(Audit(actor_id=user.id,action=f'Created scholarship {data.name}')); db.commit(); return serialize(s)
@app.put('/api/v1/admin/scholarships/{ident}')
def edit_scholarship(ident:int,data:ScholarshipInput,user:User=Depends(admin),db:Session=Depends(db)):
    s=scholarship(db,ident)
    for k,v in data.model_dump(mode='json').items(): setattr(s,k,v)
    s.verification='Needs Update'; s.verified_at=None; db.add(Audit(actor_id=user.id,action=f'Edited scholarship {ident}')); db.commit(); return serialize(s)
@app.post('/api/v1/admin/scholarships/{ident}/verify')
def verify_scholarship(ident:int,user:User=Depends(admin),db:Session=Depends(db)):
    s=scholarship(db,ident)
    if s.demo or not s.source_url.startswith('https://'): raise HTTPException(400,'Verification requires real data and an official HTTPS source')
    s.verification='Verified'; s.verified_at=date.today().isoformat(); db.add(Audit(actor_id=user.id,action=f'Verified scholarship {ident}')); db.commit(); return serialize(s)
class AssistantInput(BaseModel):
    question:str=Field(min_length=1,max_length=1000)
    scholarship_id:int|None=None
@app.post('/api/v1/assistant')
def assistant(data:AssistantInput,user:User=Depends(current),db:Session=Depends(db)):
    if data.scholarship_id:
        s=scholarship(db,data.scholarship_id); result=eligibility(db.get(Profile,user.id).data,s.rules)
        return {'answer':f'{s.name}: {result["result"]}. Deadline: {s.deadline}. Documents: {", ".join(s.documents)}. '+('This is demonstration data; there is no real application portal.' if s.demo else f'Check the provider source: {s.source_url}'),'mode':'Rules-based guidance','source_url':s.source_url}
    return {'answer':'Start by completing your profile. Recommendations compare your education, marks and family income with recorded requirements. Choose a scholarship above for its specific deadline and document checklist. After applying on an official portal, save the reference number in your tracker. Status updates in Grantly are entered by you.','mode':'Rules-based guidance','source_url':''}
@app.get('/api/v1/health')
def health(): return {'status':'ok','email_configured':bool(os.getenv('SMTP_HOST')),'assistant_mode':'rules-based'}
