import json
from datetime import datetime,timedelta,timezone
from pydantic import BaseModel
from .contracts import utcnow


class MonitoringSettings(BaseModel):
    collection_enabled: bool = True
    enrichment_enabled: bool = False
    poc_enabled: bool = False


def settings(store, values=None):
    with store.connection() as db:
        if values is not None:
            db.execute("INSERT INTO meta(key,value) VALUES('monitoring_settings',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(MonitoringSettings.model_validate(values).model_dump_json(),))
        row=db.execute("SELECT value FROM meta WHERE key='monitoring_settings' LIMIT 1").fetchone()
    return MonitoringSettings.model_validate_json(row[0]).model_dump() if row else MonitoringSettings().model_dump()


def failure_status(source,exc):
    failures=source.get('status',{}).get('failures',0)+1
    delay=[300,900,3600][min(failures-1,2)] if failures<5 else [21600,43200,86400][min(failures-5,2)]
    delay=max(delay,getattr(exc,'retry_after',0),getattr(exc,'seconds',0))
    return {'last_error':utcnow(),'error':source_error(exc),'failures':failures,'system_paused':failures>=5,
        'next_attempt':(datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat()}


def runs(store,source_id=None,limit=100):
    with store.connection() as db:
        sql='SELECT data FROM source_runs';args=[]
        if source_id: sql+=' WHERE source_id=?';args.append(source_id)
        sql+=' ORDER BY rowid DESC LIMIT ?';args.append(min(limit,200))
        return [json.loads(row[0]) for row in db.execute(sql,args).fetchall()]


def run(store,id_):
    with store.connection() as db:
        row=db.execute('SELECT data FROM source_runs WHERE id=? LIMIT 1',(id_,)).fetchone()
    if not row: raise KeyError(id_)
    return json.loads(row[0])


def update_run(store,id_,**changes):
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT data FROM source_runs WHERE id=? LIMIT 1',(id_,)).fetchone()
        data=json.loads(row[0]) if row else {}
        # Cancellation must survive a worker finishing its in-flight HTTP request.
        if data.get('state')=='cancelled': changes['state']='cancelled'
        data.update(changes)
        db.execute('INSERT INTO source_runs VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
            (id_,data['source_id'],json.dumps(data,ensure_ascii=False)))
    return data


def diagnostics(store):
    sources=store.sources(); history=runs(store,limit=200)
    counters={}
    for source in sources:
        rows=[r for r in history if r['source_id']==source['id'] and r.get('state') in ('succeeded','partial','failed')]
        ok=sum(r['state'] in ('succeeded','partial') for r in rows)
        counters[source['id']]={'checks':len(rows),'successful':ok,'success_ratio':ok/len(rows) if rows else None,
            'relevant':sum(r.get('counters',{}).get('relevant',0) for r in rows),
            'background':sum(r.get('counters',{}).get('background',0) for r in rows)}
    with store.connection() as db:
        pending={r[0]:r[1] for r in db.execute('SELECT kind,COUNT(*) FROM pending_work GROUP BY kind').fetchall()}
        recent=[{'id':r['id'],**json.loads(r['data']),'next_attempt':r['next_attempt']} for r in db.execute("SELECT id,data,next_attempt FROM pending_work WHERE kind='poc_search' ORDER BY next_attempt LIMIT 20").fetchall()]
    return {'info':store.info(),'sources':counters,'pending':pending,'poc_search':recent,'runs':history[:20],
        'settings':settings(store),'sample':'Последние 200 запусков сборщика'}


def source_error(exc):
    """Actionable diagnostics without URLs, proxy credentials or response bodies."""
    import httpx
    from .fetcher import FetchError
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return f"HTTP {code}: " + {403:'доступ запрещён издателем',404:'адрес источника не найден',
            429:'лимит запросов издателя'}.get(code,'ошибка ответа издателя')
    if isinstance(exc, httpx.ConnectError):
        if 'certificate_verify_failed' in str(exc).lower():
            return 'TLS: не удалось проверить цепочку сертификата издателя'
        return 'Не удалось установить соединение с издателем'
    if isinstance(exc, httpx.TimeoutException):
        return 'Истёк срок ожидания ответа издателя'
    messages = {'article layout not recognized':'Не распознан текст статьи издателя',
        'article body too short':'Издатель вернул неполный текст статьи',
        'response is not RSS or Atom':'Издатель вернул HTML вместо RSS/Atom',
        'malformed feed':'Ошибка структуры RSS/Atom',
        'publisher requires browser verification':'Издатель требует проверку браузером (антибот)',
        'HTML article listing not recognized':'Не распознан список публикаций HTML',
        'NVIDIA bulletin index not recognized':'Не распознан индекс бюллетеней NVIDIA'}
    if str(exc) in messages:
        return messages[str(exc)]
    if isinstance(exc, FetchError):
        return str(exc)[:200]
    return type(exc).__name__
