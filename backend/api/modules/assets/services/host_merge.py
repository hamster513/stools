"""Move host relationships immediately; source snapshots remain unchanged."""
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.modules.assets.core.groups import group_key
from api.modules.assets.models import AssetGroup, AssetGroupMember, AssetUserHost


def move_host_relations(db: Session, old_id: int, new_id: int) -> None:
    links = {(r.user_id, r.source, r.kind): r for r in db.scalars(
        select(AssetUserHost).where(AssetUserHost.asset_id == new_id)
    )}
    for row in db.scalars(select(AssetUserHost).where(AssetUserHost.asset_id == old_id)):
        key = (row.user_id, row.source, row.kind)
        target = links.get(key)
        if target is None:
            row.asset_id = new_id
            links[key] = row
        else:
            # A live relationship wins over history, then the latest source observation.
            if (row.gone_at is None, row.seen_at, row.active) > (target.gone_at is None, target.seen_at, target.active):
                target.seen_at, target.gone_at, target.active = row.seen_at, row.gone_at, row.active
            db.delete(row)
    db.execute(update(AssetGroupMember).where(AssetGroupMember.asset_id == old_id).values(asset_id=new_id))
    targets = {g.group_key: g for g in db.scalars(select(AssetGroup).where(AssetGroup.host_asset_id == new_id))}
    for group in list(db.scalars(select(AssetGroup).where(AssetGroup.host_asset_id == old_id))):
        key = group_key(local=True, domain='', host_asset_id=new_id, sid=group.sid, name=group.name)[:800]
        target = targets.get(key)
        if target is None:
            group.host_asset_id, group.group_key = new_id, key
            targets[key] = group
            continue
        members = {(r.source, r.member_sid, r.member_name): r for r in db.scalars(
            select(AssetGroupMember).where(AssetGroupMember.group_id == target.id)
        )}
        for row in db.scalars(select(AssetGroupMember).where(AssetGroupMember.group_id == group.id)):
            member_key = (row.source, row.member_sid, row.member_name)
            existing = members.get(member_key)
            if existing is None:
                row.group_id = target.id
                members[member_key] = row
            else:
                for field in ('user_id', 'member_group_id', 'asset_id', 'member_domain'):
                    if not getattr(existing, field):
                        setattr(existing, field, getattr(row, field))
                existing.primary = existing.primary or row.primary
                db.delete(row)
        db.execute(update(AssetGroupMember).where(AssetGroupMember.member_group_id == group.id).values(member_group_id=target.id))
        target.members_direct = len(members)
        target.sources = list(dict.fromkeys([*target.sources, *group.sources]))
        target.os_family = target.os_family or group.os_family
        if group.description and group.description != target.description:
            target.description = '\n'.join(filter(None, [target.description, group.description]))
        target.first_seen = min((x for x in (target.first_seen, group.first_seen) if x is not None), default=None)
        target.last_seen = max((x for x in (target.last_seen, group.last_seen) if x is not None), default=None)
        target.gone_at = max(target.gone_at, group.gone_at) if target.gone_at and group.gone_at else None
        # Flush moved memberships before the source group's ON DELETE CASCADE.
        db.flush()
        db.delete(group)
