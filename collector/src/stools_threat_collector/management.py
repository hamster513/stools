# ruff: noqa: B008
import json
from pathlib import Path
from fastapi import Depends,HTTPException,Query
from pydantic import BaseModel,Field
from . import monitoring
from .catalog import CatalogPlan,CatalogRow,build_catalog_plan,apply_catalog_plan,catalog_revision
from .contracts import Source
from .outbound_profiles import public_profiles


class ImportRows(BaseModel):
    rows: list[dict] = Field(max_length=5000)


class BulkChange(BaseModel):
    items: list[dict] = Field(max_length=5000)
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None,ge=15,le=10080)


def register(app,store,runner,reader,writer):
    @app.get('/api/v1/monitoring',dependencies=[Depends(reader)])
    def diagnostics(): return monitoring.diagnostics(store)

    @app.get('/api/v1/monitoring/settings',dependencies=[Depends(reader)])
    def settings(): return monitoring.settings(store)

    @app.put('/api/v1/monitoring/settings',dependencies=[Depends(writer)])
    def save_settings(payload:monitoring.MonitoringSettings): return monitoring.settings(store,payload.model_dump())

    @app.get('/api/v1/outbound-profiles',dependencies=[Depends(reader)])
    def profiles(): return public_profiles()

    def preview(rows):
        existing=store.sources()
        plan=build_catalog_plan(existing,rows)
        for row in plan.rows:
            try: Source.model_validate(row.source)
            except ValueError:
                row.error='Invalid source configuration';row.action='error';row.selected=False
        return plan

    @app.get('/api/v1/catalog/preview',dependencies=[Depends(reader)])
    def catalog():
        return preview(json.loads(Path(__file__).with_name('sources.json').read_text()))

    @app.post('/api/v1/sources/import/preview',dependencies=[Depends(writer)])
    def import_preview(payload:ImportRows): return preview(payload.rows)

    @app.post('/api/v1/catalog/apply',dependencies=[Depends(writer)])
    def apply(payload:CatalogPlan):
        try:
            if len(payload.rows)>5000: raise ValueError('source limit exceeded')
            result=apply_catalog_plan(store,payload,payload.expected_revision)
            with store.connection() as db:
                db.execute('INSERT INTO catalog_revisions VALUES(?,?,?)',(__import__('uuid').uuid4().hex,__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),result.model_dump_json()))
            return result
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.post('/api/v1/sources/bulk',dependencies=[Depends(writer)])
    def bulk(payload:BulkChange):
        existing=store.sources(); by_id={s['id']:s for s in existing};rows=[];conflicts=[]
        for i,item in enumerate(payload.items):
            old=by_id.get(item.get('id'))
            if not old or item.get('version')!=old['version']:
                conflicts.append(item.get('id'));continue
            values={**old,**payload.model_dump(exclude={'items'},exclude_none=True)}
            rows.append(CatalogRow(index=i,action='update',source=values,existing_id=old['id'],selected=True))
        if conflicts: raise HTTPException(409,{'message':'source version conflicts; nothing applied','ids':conflicts})
        plan=CatalogPlan(expected_revision=catalog_revision(existing),rows=rows)
        return apply(plan)

    @app.post('/api/v1/sources/{id}/preview',dependencies=[Depends(writer)])
    def source_preview(id:str):
        try: return {'job_id':runner.submit(id,preview=True)}
        except (KeyError,ValueError) as exc: raise HTTPException(409,'source unavailable or busy') from exc

    @app.get('/api/v1/runs',dependencies=[Depends(reader)])
    def runs(source_id:str|None=None,limit:int=Query(100,ge=1,le=200)):
        return {'items':monitoring.runs(store,source_id,limit)}

    @app.post('/api/v1/jobs/{id}/cancel',dependencies=[Depends(writer)])
    def cancel(id:str):
        try: return monitoring.update_run(store,id,state='cancelled',finished_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()) if monitoring.run(store,id) else None
        except KeyError as exc: raise HTTPException(404,'job not found') from exc

    @app.post('/api/v1/jobs/{id}/resume',dependencies=[Depends(writer)])
    def resume(id:str):
        try:
            old=monitoring.run(store,id)
            return {'job_id':runner.submit(old['source_id'],preview=old.get('preview',False),resume=id)}
        except (KeyError,ValueError) as exc: raise HTTPException(409,'job cannot be resumed') from exc
