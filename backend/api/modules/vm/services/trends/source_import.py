import csv
import io
import json
import zipfile
from .monitoring_contracts import SourceConfigV2

FIELDS=['name','url','adapter','publisher_id','language','region','content_scope','importance','interval_minutes','enabled','telegram_mode','telegram_channel','fallback_urls']


def parse_sources(content,filename):
    if len(content)>5*1024*1024: raise ValueError('Файл превышает 5 MiB')
    if filename.lower().endswith('.csv'):
        text=content.decode('utf-8-sig')
        try: dialect=csv.Sniffer().sniff(text[:4096],delimiters=',;\t')
        except csv.Error: dialect=csv.excel
        rows=csv.reader(io.StringIO(text),dialect);header=next(rows,[])
    elif filename.lower().endswith('.xlsx'):
        from openpyxl import load_workbook
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            if sum(i.file_size for i in archive.infolist())>50*1024*1024: raise ValueError('Распакованный XLSX слишком велик')
        workbook=load_workbook(io.BytesIO(content),read_only=True,data_only=False,keep_links=False)
        rows=workbook.active.iter_rows(values_only=True);header=next(rows,[])
    else: raise ValueError('Поддерживаются CSV и XLSX')
    header=[str(v or '').strip() for v in header]
    if len(set(header))!=len(header) or any(h not in FIELDS for h in header): raise ValueError('Неизвестные или повторяющиеся столбцы')
    result=[]
    for index,values in enumerate(rows,2):
        if index>5001: raise ValueError('Максимум 5000 строк')
        if not any(v is not None and str(v).strip() for v in values): continue
        row={k:v for k,v in zip(header,values) if v is not None and str(v).strip()}
        try:
            if any(str(v).lstrip().startswith(('=','+','@')) for v in values if v is not None): raise ValueError('Формулы не допускаются')
            if 'enabled' in row:
                flag=str(row['enabled']).lower()
                if flag not in ('true','false','1','0','да','нет'): raise ValueError('enabled: true/false')
                row['enabled']=flag in ('true','1','да')
            if 'fallback_urls' in row: row['fallback_urls']=json.loads(row['fallback_urls']) if str(row['fallback_urls']).startswith('[') else str(row['fallback_urls']).split('|')
            if not row.get('publisher_id') and row.get('url'):
                from urllib.parse import urlsplit
                parts=urlsplit(row['url'])
                row['publisher_id']=(parts.hostname or '')+('/'+parts.path.strip('/') if parts.hostname in ('t.me','medium.com','feeds.feedburner.com') else '')
            source=SourceConfigV2.model_validate(row).model_dump(mode='json')
            result.append({'line':index,'source':source,'error':None})
        except (ValueError,TypeError): result.append({'line':index,'source':row,'error':'Проверьте обязательные name/url, формат, интервал и отсутствие формул'})
    if filename.lower().endswith('.xlsx'): workbook.close()
    return result


def export_sources(sources):
    target=io.StringIO();writer=csv.DictWriter(target,fieldnames=FIELDS);writer.writeheader()
    for source in sources:
        row={k:source.get(k,'') for k in FIELDS}
        for key,value in row.items():
            if isinstance(value,list): value=json.dumps(value,ensure_ascii=False)
            if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@')): value="'"+value
            row[key]=value
        writer.writerow(row)
    return target.getvalue()
