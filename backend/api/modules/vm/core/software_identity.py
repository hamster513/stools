"""Identities shared by the Windows inventory, the NVD index and CycloneDX.

WinGet identifiers describe a product, not the installation channel. The small
alias list covers differing inventory and advisory names. Other products must
have a unique publisher/name pair in the installed NVD index.
"""
import re
from dataclasses import dataclass

from packageurl import PackageURL

_CORPORATE = re.compile(r'(?:[\s,]+(?:corporation|corp|incorporated|inc|llc|ltd|limited)\.?)+$', re.IGNORECASE)
_ARCH = re.compile(r'\s*(?:\((?:x86|x64|32-bit|64-bit)\)|\b(?:x86|x64|32-bit|64-bit))$', re.IGNORECASE)
_VENDOR_ALIASES = {'adobe_systems': 'adobe', 'mozilla_foundation': 'mozilla'}
_PRODUCT_ALIASES = {
    ('mozilla', 'mozilla_firefox'): 'firefox', ('google', 'google_chrome'): 'chrome',
    ('microsoft', 'microsoft_edge'): 'edge',
}
_LABEL = re.compile(r'\s+\((?:x64|x86|64-bit|32-bit)(?:\s+(?:x64|x86|[a-z]{2}(?:-[a-z]{2})?))?\)$', re.IGNORECASE)


def token(value):
    return re.sub(r'[\s_]+', '_', str(value or '').strip().casefold())


def product_key(publisher: str, name: str, version: str = '') -> tuple[str, str]:
    """Legacy exact normalization, including for already indexed CPEs."""
    vendor = token(_CORPORATE.sub('', str(publisher or '').strip()))
    vendor = _VENDOR_ALIASES.get(vendor, vendor)
    product = _ARCH.sub('', str(name or '').strip()).strip()
    if version:
        product = re.sub(r'\s+(?:' + re.escape(str(version)) + r'|\(' +
                         re.escape(str(version)) + r'\))$', '', product).strip()
    product = token(product)
    return vendor, _PRODUCT_ALIASES.get((vendor, product), product)


def os_family(name):
    name = token(name).replace('_', ' ')
    if re.match(r'^(?:microsoft )?windows\b', name):
        return 'windows'
    if re.search(r'\b(linux|debian|ubuntu|centos|fedora|sles|redhat|rhel|alpine)\b', name):
        return 'linux'
    if name in ('mac', 'os x', 'mac os x') or name.startswith(('macos', 'mac os ')):
        return 'macos'
    if name.startswith(('android', 'ios', 'ipados')):
        return name.split()[0]
    return ''


_GENERIC_OS = {'windows', 'microsoft windows', 'linux', 'gnu/linux', 'unix'}
_UNKNOWN_OS = {'', '-', 'unknown', 'неизвестно', 'n/a'}


def needs_os_hint(name):
    value = str(name or '').strip().casefold()
    return value in _GENERIC_OS or value in _UNKNOWN_OS


def observed_os(names):
    """Refine a generic family with a compatible release observed for this host."""
    first = ''
    for value in names:
        name = str(value or '').strip()
        if name.casefold() in _UNKNOWN_OS:
            continue
        if not first:
            first = name
        if name.casefold() not in _GENERIC_OS and (
                name == first or os_family(name) == (os_family(first) or 'linux')):
            return name
    return first


@dataclass(frozen=True)
class WindowsProduct:
    key: tuple[str, str]
    winget: str = ''
    aliases: tuple[tuple[str, str], ...] = ()

    @property
    def keys(self):
        return (self.key, *self.aliases)

    def cpe_for(self, version):
        vendor, product = (re.sub(r'([^a-z0-9_.-])', r'\\\1', x) for x in self.key)
        # Installer labels with release/build text need separate interpretation.
        release = version if re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version or '') else '*'
        return f'cpe:2.3:a:{vendor}:{product}:{release}:*:*:*:*:*:*:*'


# Confirmed desktop products. Keep distinct editions, clients, servers and
# runtimes separate. Aliases here are equivalent advisory identities only.
_WINDOWS = {
    ('the_git_development_community', 'git'): WindowsProduct(
        ('git_for_windows_project', 'git_for_windows'), 'Git.Git',
        (('gitforwindows', 'git'), ('git-scm', 'git'), ('git', 'git'))),
    ('mozilla', 'firefox'): WindowsProduct(('mozilla', 'firefox'), 'Mozilla.Firefox'),
    ('google', 'chrome'): WindowsProduct(('google', 'chrome'), 'Google.Chrome'),
    ('microsoft', 'azure_data_studio'): WindowsProduct(('microsoft', 'azure_data_studio')),
    ('fslogix', 'microsoft_fslogix_apps'): WindowsProduct(('microsoft', 'fslogix')),
    ('the_wireshark_developer_community,_https://www.wireshark.org',
     'wireshark'): WindowsProduct(('wireshark', 'wireshark')),
    ('greenshot', 'greenshot'): WindowsProduct(('getgreenshot', 'greenshot')),
    ('win.rar_gmbh', 'winrar'): WindowsProduct(('rarlab', 'winrar')),
    ('nmap_project', 'nmap'): WindowsProduct(('nmap', 'nmap')),
    ('nmap_project', 'npcap'): WindowsProduct(('nmap', 'npcap')),
    ('notepad++_team', 'notepad++'): WindowsProduct(('notepad-plus-plus', 'notepad++')),
    ('elastic', 'winlogbeat'): WindowsProduct(('elastic', 'winlogbeat')),
}


_WINGET_IDS = {entry.winget.casefold() for entry in _WINDOWS.values() if entry.winget}


def windows_candidates(row, os_name):
    """Return trusted equivalent keys, or possible exact NVD keys to verify."""
    if os_family(os_name) != 'windows' or os_family(row.get('os_name')) not in ('', 'windows'):
        return None, ()
    version = str(row.get('version') or '').strip()
    name = _LABEL.sub('', str(row.get('name') or '').strip()).strip()
    name = re.sub(r'\s+(?:version\s+)?' + re.escape(version) + r'$', '', name, flags=re.IGNORECASE)
    # Some Windows uninstall records abbreviate 7.13.0 to 7.13 in DisplayName.
    suffix = re.search(r'\s+(?:version\s+)?(\d+(?:\.\d+)+)$', name, re.IGNORECASE)
    if (suffix and re.fullmatch(r'\d+(?:\.\d+)+', version)
            and re.sub(r'(?:\.0)+$', '', suffix[1]) == re.sub(r'(?:\.0)+$', '', version)):
        name = name[:suffix.start()]
    vendor, product = product_key(row.get('publisher'), name, version)
    if not vendor or not product:
        return None, ()
    trusted = _WINDOWS.get((vendor, product))
    pid = str(row.get('purl') or row.get('product_id') or '').strip()
    winget_id = ''
    if pid.startswith('pkg:'):
        try:
            package = PackageURL.from_string(pid)
        except ValueError:
            return None, ()
        if package.type not in ('generic', 'winget') or package.version not in (None, version):
            return None, ()
        if package.type == 'winget':
            winget_id = package.name.casefold()
    elif pid.casefold().startswith('winget:'):
        winget_id = pid[7:].casefold()
    elif pid.casefold() in _WINGET_IDS:
        winget_id = pid.casefold()
    if winget_id and (not trusted or trusted.winget.casefold() != winget_id):
        return None, ()
    if trusted:
        return trusted, trusted.keys
    keys = [(vendor, product)]
    if product.startswith(vendor + '_'):
        keys.append((vendor, product[len(vendor) + 1:]))
    return None, tuple(keys)


def windows_product(row, os_name, known=()):
    trusted, candidates = windows_candidates(row, os_name)
    if trusted:
        return trusted
    hits = [key for key in candidates if key in known]
    return WindowsProduct(hits[0]) if len(hits) == 1 else None
