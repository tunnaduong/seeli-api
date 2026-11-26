"""Turns the old SQLite database into INSERT statements D1 accepts (no unistr(), no transactions).
Usage: python3 -I scripts/export-sqlite.py seeli.db > data.sql"""
import sqlite3, sys

ORDER = ['users', 'friendships', 'blocks', 'reports', 'moments', 'comments', 'admin_log',
         'identities', 'photo_views', 'device_tokens']

def lit(v):
    if v is None: return 'NULL'
    if isinstance(v, (int, float)): return repr(v)
    if isinstance(v, bytes): return "X'" + v.hex() + "'"
    return "'" + str(v).replace("'", "''") + "'"

db = sqlite3.connect(sys.argv[1])
for t in ORDER:
    cur = db.execute(f'SELECT * FROM {t}')
    cols = ', '.join(d[0] for d in cur.description)
    for row in cur:
        print(f"INSERT INTO {t} ({cols}) VALUES ({', '.join(lit(v) for v in row)});")
