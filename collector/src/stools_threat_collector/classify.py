"""Versioned, explainable rules. Text is untrusted data, never instructions."""
import re
from .monitoring_contracts import ClassificationResult, IdentifierRole

IDENTIFIER = re.compile(r'\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|BDU[:\-]\d{4}[-:]\d{3,})\b',re.I)
SECURITY = re.compile(r'vulnerab|explo(?:it|itation)|remote code|security (?:update|advisory|flaw)|zero.day|ransomware|unauthenticated|уязвим|эксплуат|выполнени[ея] код|без авторизац|ата[кч]|взлом|漏洞|利用|安全公告|远程代码|勒索',re.I)
ACTION = re.compile(r'exploit(?:ed|ing|ation)|in.the.wild|patch(?:ed| available)|attackers|new campaign|исправлен|эксплуат|новая атак|используют|正在被利用|已修复',re.I)
HISTORY = re.compile(r'history of|retrospective|historical overview|истори[яи] (?:уязвим|атак)|ретроспектив|исторический обзор|历史回顾',re.I)
NOISE = re.compile(r'disease|airline|aircraft cabin|geforce|цена|заболеван|смартфон|преми[яи]|победител|распродаж|webinar|вебинар|регистраци[яи] на',re.I)


def classify_publication(publication, source=None):
    source = source or {}
    title = publication.get('title',''); text = publication.get('text','')
    scope = source.get('content_scope','security_news')
    combined = title+'\n'+text
    ids = sorted(set(m.upper() for m in IDENTIFIER.findall(combined)) | {str(i).upper() for i in publication.get('identifiers',[]) if IDENTIFIER.fullmatch(str(i))})[:500]
    technical = scope in ('vendor_advisory','vulnerability_database') or source.get('adapter') in ('kev','msrc','nvd','github')
    historical = bool(HISTORY.search(combined[:3000])) and not ACTION.search(combined[:3000])
    roles=[]
    for identifier in ids:
        place = 'title' if identifier in title.upper() else 'text'
        body = title if place=='title' else text
        pos = body.upper().find(identifier)
        evidence = body[max(0,pos-120):pos+len(identifier)+160] if pos>=0 else identifier
        role = 'mentioned' if historical else 'primary' if place=='title' else 'actionable' if technical or SECURITY.search(evidence) else 'mentioned'
        roles.append(IdentifierRole(identifier=identifier,role=role,evidence_text=evidence,evidence_location=place if pos>=0 else 'identifier'))
    actionable = any(r.role != 'mentioned' for r in roles)
    if ids and (actionable or technical):
        category='relevant'; reason='Идентификатор уязвимости в заголовке или техническом контексте'
    elif historical or ids:
        category='uncertain'; reason='Уязвимость упомянута; актуальность и роль требуют проверки'
    elif SECURITY.search(combined):
        category='early_signal'; reason='Сообщение об угрозе без подтверждённого идентификатора'
    elif scope=='general_it' or NOISE.search(combined):
        category='background'; reason='Нет признаков сообщения об уязвимости или её эксплуатации'
    else:
        category='uncertain'; reason='Недостаточно признаков для автоматической классификации'
    return ClassificationResult(category=category,reasons=[reason],identifier_roles=roles,rule_version=1)
