"""Promote an existing account without shipping a default administrator password."""
import argparse
from sqlalchemy import select
from .main import SessionLocal, User, Audit
parser=argparse.ArgumentParser()
parser.add_argument('email')
args=parser.parse_args()
with SessionLocal() as db:
    user=db.scalar(select(User).where(User.email==args.email.lower()))
    if not user: raise SystemExit('Register this account first.')
    user.role='super_admin'
    db.add(Audit(actor_id=user.id,action='Promoted by operator CLI'))
    db.commit()
    print('Administrator role assigned.')
