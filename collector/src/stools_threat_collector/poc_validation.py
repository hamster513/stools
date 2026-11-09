"""Read-only inspection of a pinned commit. No checkout, subprocess, imports or execution."""
import base64
import hashlib
import re
from datetime import datetime,timezone
from pathlib import PurePosixPath
from urllib.parse import quote
from .monitoring_contracts import PocCandidate, PocEvidence
from .poc_search import github_get

TEXT_EXTENSIONS={'.md','.txt','.py','.rb','.go','.c','.cpp','.h','.js','.ts','.sh','.ps1','.rs','.java','.yaml','.yml'}


def validate_poc(candidate,fetcher,previous=None,now=None):
    now=now or datetime.now(timezone.utc)
    data=PocCandidate.model_validate(candidate).model_dump(mode='json')
    try:
        repo=github_get(fetcher,f'https://api.github.com/repositories/{data["repository_id"]}')
        name=repo['full_name']
        if repo['id']!=data['repository_id'] or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',name):
            raise ValueError('repository identity changed')
        base='https://api.github.com/repos/'+name
        commit=github_get(fetcher,base+'/commits/'+quote(repo['default_branch'],safe=''))['sha']
        if not re.fullmatch(r'[a-f0-9]{40,64}',commit): raise ValueError('invalid commit SHA')
        tree=github_get(fetcher,base+'/git/trees/'+commit+'?recursive=1')
        entries=[e for e in tree['tree'] if e.get('type')=='blob' and e.get('mode') in ('100644','100755')
            and PurePosixPath(e['path']).suffix.lower() in TEXT_EXTENSIONS and not e['path'].startswith(('.git/','.github/workflows/'))]
        entries.sort(key=lambda e:(not PurePosixPath(e['path']).name.lower().startswith('readme'),e.get('size',0),e['path']))
        truncated=bool(tree.get('truncated')) or len(entries)>50
        files=[]; size=0
        for entry in entries[:50]:
            if entry.get('size',0)>262144 or size+entry.get('size',0)>2*1024*1024:
                truncated=True; continue
            sha=entry['sha']
            if not re.fullmatch(r'[a-f0-9]{40,64}',sha): raise ValueError('invalid blob SHA')
            blob=github_get(fetcher,base+'/git/blobs/'+sha)
            if blob.get('encoding')!='base64': truncated=True; continue
            raw=base64.b64decode(blob['content'])
            if len(raw)>262144 or size+len(raw)>2*1024*1024: truncated=True; continue
            size+=len(raw)
            if b'\x00' in raw: continue
            try: text=raw.decode('utf-8')
            except UnicodeDecodeError: continue
            files.append((entry['path'],text,hashlib.sha256(raw).hexdigest()))
        readme='\n'.join(t for p,t,h in files if PurePosixPath(p).suffix.lower() in ('.md','.txt'))
        code=[(p,t,h) for p,t,h in files if PurePosixPath(p).suffix.lower() not in ('.md','.txt','.yaml','.yml')]
        identifier = re.compile(r'\b'+re.escape(data['cve_id'])+r'\b',re.I)
        exact=bool(identifier.search(readme))
        reproduction=bool(re.search(r'reproduce|proof.of.concept|usage:|python .*(?:poc|exploit)|воспроизвед|复现',readme,re.I))
        meaningful=[(p,t,h) for p,t,h in code if re.search(r'payload|exploit|requests\.(?:post|put)|socket|memcpy|fetch\(|curl ',t,re.I)]
        list_only=bool(re.search(r'vulnerability scanner|CVE list|awesome[- ]|сканер уязвим',readme,re.I)) or len(set(re.findall(r'CVE-\d{4}-\d{4,}',readme,re.I)))>10
        likely=exact and reproduction and bool(meaningful) and not list_only and not truncated
        evidence=[]
        for path,text,digest in files:
            if identifier.search(text) or any(path==p for p,t,h in meaningful):
                match=identifier.search(text);pos=match.start() if match else 0
                evidence.append(PocEvidence(path=path,url=f'https://github.com/{name}/blob/{commit}/{quote(path,safe="/")}',sha256=digest,quote=text[max(0,pos-80):pos+600]))
        parent=repo.get('source',{}).get('id') or repo.get('parent',{}).get('id')
        data.update(repository_name=name,url='https://github.com/'+name,commit_sha=commit,fork_parent=parent,
            family_id='github:'+str(parent or repo['id']),state='likely' if likely else 'candidate',
            signals=[label for valid,label in [(exact,'точная CVE в документации'),(reproduction,'описание воспроизведения'),(bool(meaningful),'код с признаками воспроизведения'),(list_only,'список или сканер')] if valid],
            evidence=evidence[:50],reason='Статические признаки PoC; работоспособность не проверялась' if likely else 'Недостаточно статических доказательств PoC',
            checked_at=now,incomplete=truncated,error='')
        return PocCandidate.model_validate(data)
    except Exception as exc:
        return PocCandidate.model_validate({**(previous or data),'incomplete':True,'error':type(exc).__name__})
