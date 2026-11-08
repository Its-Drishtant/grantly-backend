import os
from datetime import datetime
from zoneinfo import ZoneInfo
from celery import Celery
from celery.schedules import crontab
from sqlalchemy import select
from .main import SessionLocal, Application, Scholarship, Preferences, Notification, User, mail

celery=Celery('grantly',broker=os.getenv('REDIS_URL','redis://localhost:6379/0'))
celery.conf.beat_schedule={'deadlines':{'task':'grantly.reminders','schedule':crontab(minute=0)}}
@celery.task(name='grantly.reminders')
def reminders():
    with SessionLocal() as db:
        for a in db.scalars(select(Application).where(Application.archived==False)):
            if a.status in ('Approved','Rejected','Submitted','Under Review'): continue
            p=db.get(Preferences,a.user_id); s=db.get(Scholarship,a.scholarship_id)
            now=datetime.now(ZoneInfo(p.timezone))
            if now.hour!=9: continue
            days=(datetime.fromisoformat(s.deadline).date()-now.date()).days
            if days not in (30,15,7,3,1): continue
            key=f'deadline:{a.id}:{s.deadline}:{days}'
            if db.scalar(select(Notification).where(Notification.user_id==a.user_id,Notification.dedupe==key)): continue
            title=f'{days} days left: {s.name}'
            if p.in_app or p.email:
                db.add(Notification(user_id=a.user_id,title=title,body='Prepare your documents and check the official application portal.',dedupe=key,read=not p.in_app)); db.commit()
            if p.email: mail(db.get(User,a.user_id).email,title,'Your tracked scholarship deadline is approaching. Check your Grantly workspace.')
