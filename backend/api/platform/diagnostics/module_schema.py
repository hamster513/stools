"""Additional inventory fields in native diagnostic packages, beyond legacy dossiers."""
MODULE_EXTRA_FIELDS = {
    "asset": {"tags", "pinned"},
    "asset_user": {"tags"},
    "asset_group_gpo": {"hosts", "hosts_total"},
}
PIN_FIELDS = {"name", "fqdn", "domain", "ip", "os", "network_id", "criticality"}
