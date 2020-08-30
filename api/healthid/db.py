from tinydb import TinyDB, where
from os import makedirs
makedirs('.db', exist_ok=True)
db = TinyDB('.db/db.json')

accounts = db.table('account')
challenges = db.table('challenge')
codes = db.table('codes')
auditlog = db.table('auditlog')
patients = db.table('patients')
