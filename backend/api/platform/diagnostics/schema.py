"""Explicit diagnostic wire schema; adding model columns never expands exports."""
from api.modules.ad import models as ad
from api.modules.assets import models as assets
from api.modules.ksc import models as ksc

SPECS = {
    assets.Asset: 'id name name_key fqdn domain ip first_seen last_seen criticality',
    assets.AssetObservation: 'id asset_id source source_key name fqdn domain ip ips seen_at gone_at extra',
    assets.AssetUser: 'id sid name_key sam upn display_name domain local enabled privileged first_seen last_seen',
    assets.AssetUserObservation: 'id user_id source source_key seen_at gone_at data',
    assets.AssetUserHost: 'id user_id asset_id source kind active seen_at gone_at',
    assets.AssetUserGroup: 'id user_id group_sid group_name direct source',
    assets.AssetGroup: 'id group_key sid name domain local os_family host_asset_id sources in_ad first_seen last_seen gone_at',
    assets.AssetGroupMember: 'id group_id member_kind user_id member_group_id asset_id member_sid member_name member_domain primary source',
    assets.AssetGroupGpo: 'id domain group_sid group_name local_group local_group_sid via action gpo_name gpo_dn filtered seen_at',
    ad.AdDomain: 'id sid dns_root dn netbios',
    ad.AdSnapshot: 'id domain_id collected_at source objects',
    ksc.KscServer: 'id name',
    ksc.KscSnapshot: 'id server_id collected_at source hosts policy_store_version',
    ksc.KscHost: 'id snapshot_id host_id name fqdn domain group_path group_id ip agent_installed agent_alive last_seen_at protection rtp_state bases_at last_fullscan_at status threats unassigned in_ad',
    ksc.KscPolicy: 'id snapshot_id policy_id name group_id group_path active accept_parent modified_at has_contents contents_partial described groups hosts profiles exclusions net_rules settings_total settings_known',
    ksc.KscPolicyScope: 'id snapshot_id policy_id group_id group_path own hosts',
    ksc.KscProfile: 'id snapshot_id policy_id name enabled priority settings',
    ksc.KscNetRule: 'id snapshot_id policy_id profile layer position name action direction protocol local_ports remote_ports enabled key',
    ksc.KscPolicyFirewall: 'id snapshot_id policy_id profile enabled notify_only hips_enabled hips_notify_only component_enabled hips_component_enabled default_app_group',
}
TABLE_MODELS = {model.__tablename__: model for model in SPECS}
FIELDS = {model.__tablename__: set(fields.split()) for model, fields in SPECS.items()}
AD_OBJECT_FIELDS = {'dn', 'class', 'sid', 'sam', 'name', 'uac', 'primaryGroupID', 'member', 'displayName', 'userPrincipalName', 'dNSHostName', 'whenCreated', 'whenChanged', 'gpLink', 'gpOptions', 'flags'}
AD_DOMAIN_FIELDS = {'dn', 'sid', 'dns_root', 'netbios'}
WARNINGS = [
    'Пакет содержит выбранные связи; посторонние объекты и история снимков исключены.',
    'Состав групп ограничен выбранными объектами и цепочками вложенности; все группы выбранных учётных записей сохранены. Полный размер групп и списки хостов GPO не включены.',
    'Членство из последнего снимка AD и кеша Assets сохранено независимо; расхождения намеренно оставлены.',
    'Имена и идентификаторы заменены; все исходные даты сдвинуты на одинаковый ненулевой интервал.',
    'Исключены свободный текст, секреты, исходные ответы, находки, ПО, подключения, задания, SYSVOL и дескрипторы безопасности.',
    'Исключены условия активации профилей KSC, исключения защиты, адресные условия межсетевого экрана и подробные настройки; по метаданным правил нельзя определить фактическую защиту.',
    'Неподдерживаемые поля исключены; исходные данные могли быть собраны не полностью.',
]


class BundleError(ValueError):
    """Errors must never embed source values, paths or parser messages."""
