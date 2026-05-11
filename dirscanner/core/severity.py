"""
Severity classification for discovered open directory listings.

Severity levels and their meaning:

    CRITICAL — credential files, SSH keys, shell history, private keys
    HIGH     — source control metadata, backup archives, admin panels, config
    MEDIUM   — uploads, data directories, logs, database dumps
    LOW      — generic static assets (images, CSS, fonts, etc.)
    INFO     — everything else

Rules are evaluated in order; the first match wins.
"""

# (severity, [substring patterns]) — evaluated top-to-bottom, first match wins.
_RULES: list[tuple[str, list[str]]] = [
    ("critical", [
        ".ssh/",
        "id_rsa",
        "id_rsa.pub",
        ".bash_history",
        ".mysql_history",
        ".sh_history",
        ".history/",
        "known_hosts",
        ".htpasswd",
        ".passwd/",
        "passwd/",
        "authorized_keys",
        "private/",
        "secret/",
        "secrets/",
        ".env",
        "credentials",
        "private_key",
    ]),
    ("high", [
        ".git/",
        ".svn/",
        "CVS/",
        ".cvs/",
        "admin/",
        "admin_",
        "administrator/",
        "administration/",
        "adminpanel/",
        "backup/",
        "backups/",
        "back-up/",
        "bak/",
        "db/",
        "database/",
        "dbadmin/",
        "phpmyadmin/",
        "myadmin/",
        "pma/",
        "config/",
        "configs/",
        "configuration/",
        ".htaccess",
        "wp-admin/",
        "wp-login/",
        "cpanel/",
        "webadmin/",
        "panel/",
        "controlpanel/",
        "control/",
        "logs/",
        "log/",
        "server/",
        "sql/",
        "dump/",
        "dumps/",
        "install/",
        "setup/",
        "source/",
        "src/",
        "conf/",
        "env/",
        "etc/",
    ]),
    ("medium", [
        "uploads/",
        "upload/",
        "data/",
        "files/",
        "tmp/",
        "temp/",
        "cache/",
        "download/",
        "downloads/",
        "media/",
        "storage/",
        "export/",
        "exports/",
        "report/",
        "reports/",
        "docs/",
        "documents/",
        "attachments/",
        "user/",
        "users/",
        "members/",
        "accounts/",
        "billing/",
        "invoices/",
        "archive/",
        "archives/",
        "old/",
        "dev/",
        "devel/",
        "test/",
        "staging/",
        "debug/",
        "error/",
        "errors/",
        "var/",
        "bin/",
        "cgi-bin/",
        "cgi/",
        "api/",
        "webmail/",
    ]),
    ("low", [
        "images/",
        "img/",
        "css/",
        "js/",
        "fonts/",
        "static/",
        "assets/",
        "public/",
        "content/",
        "includes/",
        "lib/",
        "libs/",
        "vendor/",
        "themes/",
        "templates/",
        "icons/",
        "audio/",
        "video/",
        "gallery/",
        "photos/",
    ]),
]


def classify_severity(path: str) -> str:
    """Return a severity label for a given URL path.

    Args:
        path: The URL path component, e.g. ``/admin/`` or ``backup/``.
            Leading slashes and casing are normalised before matching.

    Returns:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        or ``"info"``.
    """
    normalised = path.lower().lstrip("/")
    for severity, patterns in _RULES:
        for pattern in patterns:
            if normalised.startswith(pattern.lstrip("/")) or pattern in normalised:
                return severity
    return "info"
