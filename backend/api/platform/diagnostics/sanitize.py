"""Per-package irreversible labels. No original value or mapping is serialized."""
import datetime as dt
import hashlib
import hmac
import ipaddress
import re
import secrets

from .schema import BundleError


class Anonymizer:
    def __init__(self):
        self.secret = secrets.token_bytes(32)
        self.offset = dt.timedelta(days=(secrets.randbelow(365) + 1) * secrets.choice((-1, 1)))
        self.ids = {}
        self.addresses = {}
        self.directory_labels = {}

    def token(self, value, category='entity'):
        if not value:
            return ''
        digest = hmac.new(self.secret, (category + ':' + str(value).casefold()).encode(), hashlib.sha256).hexdigest()[:16]
        return f'{category}-{digest}'

    def identifier(self, namespace, value):
        if value is None:
            return None
        mapping = self.ids.setdefault(namespace, {})
        if value not in mapping:
            mapping[value] = len(mapping) + 1
        return mapping[value]

    def domain(self, value):
        return self.token(value, 'domain') + '.invalid' if value else ''

    def name(self, value):
        if not value:
            return ''
        return self.token(str(value).rstrip('$'))

    def fqdn(self, value):
        if not value:
            return ''
        head, sep, tail = value.partition('.')
        return self.name(head) + ('.' + self.domain(tail) if sep else '')

    def register_directory_domain(self, dns_root, netbios):
        # Display principals use AD's NetBIOS prefix, falling back to DNS only
        # when the export has no NetBIOS name. Canonical user keys always use DNS.
        if dns_root:
            self.directory_labels.setdefault(dns_root.casefold(), self.domain(dns_root))
        if netbios:
            self.directory_labels[netbios.casefold()] = self.name(netbios)

    def principal(self, value, *, directory=False):
        if not value:
            return ''
        if '@' in value:
            name, domain = value.rsplit('@', 1)
            return self.name(name) + '@' + self.domain(domain)
        if '\\' in value:
            domain, name = value.rsplit('\\', 1)
            label = self.directory_labels.get(domain.casefold(), self.name(domain)) if directory else self.domain(domain)
            return label + '\\' + self.name(name)
        return self.name(value)

    def sid(self, value):
        if not value:
            return ''
        parts = str(value).split('-')
        if re.fullmatch(r'S-1-5-21-\d+-\d+-\d+(?:-\d+)?', str(value), re.IGNORECASE):
            base = '-'.join(parts[:7])
            digest = hmac.new(self.secret, base.lower().encode(), hashlib.sha256).digest()
            result = 'S-1-5-21-' + '-'.join(str(int.from_bytes(digest[i:i+4], 'big')) for i in (0, 4, 8))
            # RID semantics (primary and built-in AD groups) must survive.
            return result + ('-' + parts[7] if len(parts) == 8 else '')
        if re.fullmatch(r'S-1-(?:5-32-\d+|5-(?:9|10|11|18|19|20)|1-0|3-\d+)', str(value), re.IGNORECASE):
            return str(value).upper()
        return 'S-1-5-21-0-0-0-' + str(self.identifier('other_sid', str(value).lower()))

    def dn(self, value):
        if not value:
            return ''
        parts = re.split(r'(?<!\\),', str(value))
        result = []
        for part in parts:
            key, sep, val = part.strip().partition('=')
            if not sep or key.lower() not in {'dc', 'cn', 'ou'}:
                raise BundleError('Unsupported directory identity.')
            # FSP names embed a SID; preserve their relationship to account identities.
            label = self.sid(val) if val.upper().startswith('S-1-') else self.token(val)
            result.append(key.upper() + '=' + label)
        return ','.join(result)

    def ip(self, value):
        if not value:
            return ''
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return ''
        key = str(address)
        index = self.identifier('ip' + str(address.version), key)
        if address.version == 4:
            return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.0')) + index))
        return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('2001:db8::')) + index))

    def date(self, value):
        if value is None:
            return None
        if not isinstance(value, dt.datetime):
            value = dt.datetime.fromisoformat(value)
        try:
            return (value + self.offset).isoformat()
        except (OverflowError, ValueError):
            raise BundleError('Unsupported timestamp.') from None

    def gp_link(self, value):
        if value is None:
            return None
        parts = re.findall(r'\[LDAP://(.+?);(\d+)\]', value, re.IGNORECASE)
        if ''.join('[LDAP://' + dn + ';' + flags + ']' for dn, flags in parts).casefold() != value.casefold():
            raise BundleError('Unsupported directory policy link.')
        return ''.join('[LDAP://' + self.dn(dn) + ';' + flags + ']' for dn, flags in parts)
