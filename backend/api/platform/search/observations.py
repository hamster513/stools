"""Display only selected inventory/account fields, never raw source payloads."""

from sqlalchemy import select

from api.modules.assets.models import Asset, AssetObservation, AssetUser, AssetUserObservation
from api.modules.toolbox.services.lookup_types import facts
from api.platform.services.access import allows

from .models import Row, Section
from .relations import entity, fill


def observations(db, obj, access):
    section = Section(
        id="observations",
        title="Наблюдения источников",
        note="Дата — время сбора источника, не время поиска. Исторические записи отмечены отдельно.",
    )
    allowed = [s for s in ("ad", "ksc", "vm") if allows(access, s, "read")]
    if isinstance(obj, Asset):
        model = AssetObservation
        condition = model.asset_id == obj.id
        allowed += ["dns", "rt", "network"]
    elif isinstance(obj, AssetUser):
        model = AssetUserObservation
        condition = model.user_id == obj.id
    else:
        section.note = "Источники и время членства показаны в составе и связях группы."
        return section
    observations = db.scalars(
        select(model)
        .where(condition, model.source.in_(allowed))
        .order_by(model.source, model.id)
        .limit(101)
    ).all()
    rows = []
    for obs in observations:
        values = {}
        if isinstance(obj, Asset):
            for label, field in [("Имя", "name"), ("FQDN", "fqdn"), ("IP", "ip"), ("ОС", "os")]:
                value = getattr(obs, field)
                if value and value != getattr(obj, field):
                    values[label] = value
            if obs.ips and set(obs.ips) != {obj.ip}:
                values["Адреса источника"] = ", ".join(obs.ips)
        else:
            for key, label in [
                ("mail", "Почта"),
                ("department", "Подразделение"),
                ("title", "Должность"),
                ("last_logon", "Последний вход"),
                ("password_last_set", "Пароль изменён"),
            ]:
                value = (obs.data or {}).get(key)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    values[label] = str(value)
        rows.append(
            Row(
                id=str(obs.id),
                title=obs.source.upper(),
                href=entity(obj).href,
                source=obs.source.upper(),
                observed_at=obs.seen_at,
                reason="Историческое наблюдение (источник больше не подтверждает объект)"
                if obs.gone_at
                else "Последнее сохранённое наблюдение",
                facts=facts(**values),
            )
        )
    return fill(section, rows)
