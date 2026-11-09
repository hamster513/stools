"""Conservative local range matching; exact scanner evidence always wins."""
import re


def numeric(value):
    if not re.fullmatch(r'\d+(?:\.\d+)*',str(value or '')):
        return None
    return tuple(int(p) for p in value.split('.'))


def compare(left,right):
    a=numeric(left); b=numeric(right)
    if a is None or b is None: return None
    n=max(len(a),len(b)); a+= (0,)*(n-len(a)); b+=(0,)*(n-len(b))
    return (a>b)-(a<b)


def evaluate_applicability(item, enrichment, exact_scanner=False):
    result={'local_ref':item['local_ref'],'state':'unknown','confidence_kind':'version_candidate',
        'reasons':[],'provider_refs':enrichment.get('references',[])}
    if exact_scanner:
        return {**result,'state':'affected','confidence_kind':'exact_scanner','reasons':['Совпадение идентификатора в результатах сканера; диапазон не отменяет находку']}
    matching=[r for r in enrichment.get('cpe_matches',[]) if r.get('product','').lower()==item.get('product','').lower()
        and r.get('vendor','').lower()==item.get('vendor','').lower() and r.get('ecosystem','generic')==item.get('ecosystem','generic')]
    if not matching or numeric(item.get('version')) is None:
        result['reasons']=['Не хватает точного продукта, поставщика, экосистемы или поддерживаемой версии']; return result
    states=[]
    for row in matching:
        checks=[]
        for key,op in [('versionStartIncluding',lambda x:x>=0),('versionStartExcluding',lambda x:x>0),
                       ('versionEndIncluding',lambda x:x<=0),('versionEndExcluding',lambda x:x<0)]:
            if key in row:
                c=compare(item['version'],row[key]); checks.append(None if c is None else op(c))
        if row.get('version') not in ('*','-',None,''):
            c=compare(item['version'],row['version']); checks.append(None if c is None else c==0)
        if not checks or None in checks: states.append('unknown')
        elif all(checks): states.append('affected' if row.get('complete') else 'unknown')
        else: states.append('not_affected' if row.get('complete') else 'unknown')
    result['state']='affected' if 'affected' in states else 'not_affected' if set(states)=={'not_affected'} else 'unknown'
    result['reasons']=['Сопоставлены точные продукт/поставщик и числовой диапазон' if result['state']!='unknown' else 'Неполная логика диапазона или CPE; нужна проверка']
    return result
