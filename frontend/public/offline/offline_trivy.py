"""Official registry download shared by the standalone kit and the VM server."""

from trivy_db_archive import REGISTRIES, TOKEN_URL, download_database

__all__ = ["REGISTRIES", "TOKEN_URL", "download_database"]
