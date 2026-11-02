"""Hash-linked egress events. An independent exported checkpoint anchors the tail."""
import hashlib
import json
from functools import wraps
from threading import RLock

_LOCK=RLock()

def serialized(function):
    @wraps(function)
    def call(*args,**kwargs):
        with _LOCK:return function(*args,**kwargs)
    return call

FIELDS=('id','program','host','port','decision','reason','tool','run_id','policy_version','resolved_ip','transport','created','chain_origin')
GENESIS='0'*64

def digest(row,previous):
    fields=FIELDS+('event_version','method','path_hash','injected_headers') if row.get('event_version',1) in {2,3} else FIELDS
    if row.get('event_version',1)==3:fields+=('source',)
    payload={key:row[key] for key in fields}
    return hashlib.sha256((previous+'\n'+json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True)).encode()).hexdigest()

@serialized
def migrate(connection):
    connection.execute('BEGIN IMMEDIATE')
    try:
        columns={row[1] for row in connection.execute('PRAGMA table_info(egress_events)')}
        for column in ('prev_hash','event_hash','chain_origin'):
            if column not in columns:connection.execute('ALTER TABLE egress_events ADD COLUMN '+column+' TEXT')
        for column,definition in [('event_version','INTEGER NOT NULL DEFAULT 1'),('method','TEXT'),('path_hash','TEXT'),('injected_headers','TEXT'),('source','TEXT')]:
            if column not in columns:connection.execute('ALTER TABLE egress_events ADD COLUMN '+column+' '+definition)
        # Only the schema migration may anchor old rows; later missing hashes are
        # evidence of damage, never silently repaired on opening a workspace.
        if 'event_hash' not in columns:
            previous=GENESIS
            for source in connection.execute('SELECT * FROM egress_events ORDER BY id').fetchall():
                row=dict(source);row['chain_origin']='legacy-backfill'
                value=digest(row,previous)
                connection.execute('UPDATE egress_events SET prev_hash=?,event_hash=?,chain_origin=? WHERE id=?',(previous,value,row['chain_origin'],row['id']))
                previous=value
        connection.commit()
    except BaseException:connection.rollback();raise

@serialized
def append(connection,values,details=None):
    connection.execute('BEGIN IMMEDIATE')
    try:
        details=details or {}
        tail=connection.execute('SELECT event_hash FROM egress_events ORDER BY id DESC LIMIT 1').fetchone()
        previous=tail[0] if tail else GENESIS
        if previous is None:raise ValueError('Audit chain is damaged; refusing to append')
        cursor=connection.execute('''INSERT INTO egress_events
            (program,host,port,decision,reason,tool,run_id,policy_version,resolved_ip,transport,created,prev_hash,chain_origin,event_version,method,path_hash,injected_headers,source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(*values,previous,'native',3,details.get('method'),details.get('path_hash'),json.dumps(details.get('injected_headers',[]),sort_keys=True),details.get('source')))
        row=dict(connection.execute('SELECT * FROM egress_events WHERE id=?',(cursor.lastrowid,)).fetchone())
        connection.execute('UPDATE egress_events SET event_hash=? WHERE id=?',(digest(row,previous),cursor.lastrowid))
        connection.commit()
    except BaseException:connection.rollback();raise

@serialized
def verify(connection,checkpoint=None):
    # A stable read transaction prevents concurrent appends from mixing snapshots.
    connection.execute('BEGIN')
    try:rows=connection.execute('SELECT * FROM egress_events ORDER BY id').fetchall()
    finally:connection.rollback()
    previous=GENESIS;legacy=0;last_id=0
    for source in rows:
        row=dict(source)
        if row.get('event_version',1) not in {1,2,3}:return {'valid':False,'first_bad_id':row['id'],'reason':'unknown-event-version'}
        if row['prev_hash']!=previous or row['event_hash']!=digest(row,previous):
            return {'valid':False,'first_bad_id':row['id'],'checked':last_id,'reason':'hash-chain-mismatch'}
        if row['chain_origin']=='legacy-backfill':legacy+=1
        if row['chain_origin'] not in {'legacy-backfill','native'}:
            return {'valid':False,'first_bad_id':row['id'],'reason':'invalid-chain-origin'}
        previous=row['event_hash'];last_id=row['id']
    anchor={'last_id':last_id,'event_hash':previous,'count':len(rows)}
    if checkpoint is not None:
        if not isinstance(checkpoint,dict) or set(checkpoint)!={'last_id','event_hash','count'}:
            raise ValueError('Invalid audit checkpoint')
        prefix=next((dict(r) for r in rows if r['id']==checkpoint['last_id']),None)
        matches=(checkpoint=={'last_id':0,'event_hash':GENESIS,'count':0}) or (prefix is not None and prefix['event_hash']==checkpoint['event_hash'] and sum(r['id']<=checkpoint['last_id'] for r in rows)==checkpoint['count'])
        if not matches:return {'valid':False,'reason':'checkpoint-mismatch-or-truncation','checkpoint':anchor}
    return {'valid':True,'checked':len(rows),'legacy_rows':legacy,'checkpoint':anchor,
            'limitation':'Without an independently retained checkpoint, tail deletion or a full chain rewrite is not detectable.'}
