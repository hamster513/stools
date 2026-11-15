#!/usr/bin/env python3
"""STools Threat Hunting: public sources -> offline ZIP (Python 3.11+, stdlib).

python3 download-intel.py --output hunting.zip
python3 download-intel.py --list-sources
python3 download-intel.py --only sigmahq,elastic --output rules.zip
RSS history is limited by the publisher. --days 0 keeps all available feed items.
--articles also fetches HTML articles; it never downloads/executes attachments.
Exit 0: complete, 2: partial archive, 1: no usable data / invalid configuration.
HTTPS_PROXY/HTTP_PROXY and SSL_CERT_FILE use standard Python behavior.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

import tomllib

MAX_DATA = 128 * 1024 * 1024
MAX_ITEMS = 30_000
MAX_TEXT = 1_048_576
TECHNIQUE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)
DEFAULT_SOURCES = [
    {'id': 'feed-1068f4274c8f1e06', 'name': 'CERT-FR alerts', 'kind': 'rss', 'url': 'https://cert.cyber.gouv.fr/alerte/feed/'},
    {'id': 'feed-3fb34b2c7c63e46e', 'name': 'CERT-FR advisories', 'kind': 'rss', 'url': 'https://cert.cyber.gouv.fr/avis/feed/'},
    {'id': 'feed-2f06909effebe4c4', 'name': 'CERT-EU', 'kind': 'rss', 'url': 'https://cert.europa.eu/publications/security-advisories-rss'},
    {'id': 'feed-7afaa499e4044f41', 'name': 'NCSC NL', 'kind': 'rss', 'url': 'https://advisories.ncsc.nl/rss/advisories'},
    {'id': 'feed-50f1c381f7716113', 'name': 'Heise Security', 'kind': 'rss', 'url': 'https://www.heise.de/security/feed.xml'},
    {'id': 'feed-833a9405841feb40', 'name': 'ESET WeLiveSecurity', 'kind': 'rss', 'url': 'https://www.welivesecurity.com/en/rss/feed/'},
    {'id': 'feed-af87040a84c933db', 'name': 'Seebug Paper', 'kind': 'rss', 'url': 'https://paper.seebug.org/rss'},
    {'id': 'feed-9bde347a0bcba123', 'name': 'NSFOCUS', 'kind': 'rss', 'url': 'https://blog.nsfocus.net/feed/'},
    {'id': 'feed-d65d05538565e200', 'name': '360CERT', 'kind': 'rss', 'url': 'https://cert.360.cn/daily/feed'},
    {'id': 'feed-bbb7eda27c748ca5', 'name': 'Securelist', 'kind': 'rss', 'url': 'https://securelist.ru/feed/'},
    {'id': 'feed-1f81d68bb668721d', 'name': 'SecurityLab', 'kind': 'rss', 'url': 'https://www.securitylab.ru/_services/export/rss/'},
    {'id': 'feed-50fbf262f48afdcf', 'name': 'BleepingComputer', 'kind': 'rss', 'url': 'https://www.bleepingcomputer.com/feed/'},
    {'id': 'feed-636032c91a0b4c9a', 'name': 'The Hacker News', 'kind': 'rss', 'url': 'https://feeds.feedburner.com/TheHackersNews'},
    {'id': 'feed-cf55617878869ccb', 'name': 'AWS Security Blog', 'kind': 'rss', 'url': 'https://aws.amazon.com/blogs/security/feed/'},
    {'id': 'feed-46991864eec79b0b', 'name': 'Intigriti Blog', 'kind': 'rss', 'url': 'https://www.intigriti.com/blog/feed'},
    {'id': 'feed-15c85dceadfab3fe', 'name': 'JetBrains Security', 'kind': 'rss', 'url': 'https://blog.jetbrains.com/security/feed/'},
    {'id': 'feed-7e6e6cdbd15ded86', 'name': 'Cisco Talos Intelligence', 'kind': 'rss', 'url': 'https://blog.talosintelligence.com/rss/'},
    {'id': 'feed-e962f40b631cc14b', 'name': 'YesWeHack Blog', 'kind': 'rss', 'url': 'https://www.yeswehack.com/rss.xml'},
    {'id': 'feed-7fb4d8472f9b0073', 'name': 'Cisco Security Blog', 'kind': 'rss', 'url': 'https://blogs.cisco.com/security/feed'},
    {'id': 'feed-2d8619a93995b24e', 'name': 'VMware Security', 'kind': 'rss', 'url': 'https://blogs.vmware.com/security/feed'},
    {'id': 'feed-250ee0d7f6744812', 'name': 'Bug Alert Critical', 'kind': 'rss', 'url': 'https://bugalert.org/feeds/critical-severity.atom.xml'},
    {'id': 'feed-f0010d581d94382b', 'name': 'CVEFeed Recent Vulnerabilities', 'kind': 'rss', 'url': 'https://cvefeed.io/rssfeed/latest.xml'},
    {'id': 'feed-78512d10a4f25527', 'name': 'DEV Security', 'kind': 'rss', 'url': 'https://dev.to/feed/tag/security'},
    {'id': 'feed-d9bfd43d294b1f79', 'name': 'Google Developers Blog', 'kind': 'rss', 'url': 'https://developers.googleblog.com/feeds/posts/default/'},
    {'id': 'feed-329c7052b8a81741', 'name': 'Troy Hunt', 'kind': 'rss', 'url': 'https://feeds.feedburner.com/TroyHunt'},
    {'id': 'feed-2440ad173eddba6d', 'name': 'Fortinet Threat Research', 'kind': 'rss', 'url': 'https://feeds.fortinet.com/fortinet/blog/threat-research'},
    {'id': 'feed-3903b1582d75bc31', 'name': 'Fortinet PSIRT', 'kind': 'rss', 'url': 'https://filestore.fortinet.com/fortiguard/rss/ir.xml'},
    {'id': 'feed-00ccaac43d3fc7cc', 'name': 'ForkLog', 'kind': 'rss', 'url': 'https://forklog.com/feed'},
    {'id': 'feed-d6b2730ca0f4c447', 'name': 'GBHackers', 'kind': 'rss', 'url': 'https://gbhackers.com/feed/'},
    {'id': 'feed-d37e51a72fa9a446', 'name': 'GitHub Security', 'kind': 'rss', 'url': 'https://github.blog/security/feed/'},
    {'id': 'feed-67c1afb569308d2a', 'name': 'Habr Information Security', 'kind': 'rss', 'url': 'https://habr.com/ru/rss/hubs/infosecurity/articles/all/?fl=ru'},
    {'id': 'feed-7152508e7789b9fb', 'name': 'SANS Internet Storm Center', 'kind': 'rss', 'url': 'https://isc.sans.edu/rssfeed.xml'},
    {'id': 'feed-9f2d692b80a4d47b', 'name': 'Krebs on Security', 'kind': 'rss', 'url': 'https://krebsonsecurity.com/feed/'},
    {'id': 'feed-d9ec618eb75b69be', 'name': 'Kubernetes Security Announcements', 'kind': 'rss', 'url': 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml'},
    {'id': 'feed-ed24c6bd27df75e3', 'name': 'Lobsters Security', 'kind': 'rss', 'url': 'https://lobste.rs/t/security.rss'},
    {'id': 'feed-ff4148a52cccd7a8', 'name': 'InfoSec Write-ups', 'kind': 'rss', 'url': 'https://medium.com/feed/bugbountywriteup'},
    {'id': 'feed-7b952789865c779d', 'name': 'Knownsec 404 Medium', 'kind': 'rss', 'url': 'https://medium.com/feed/@knownsec404team'},
    {'id': 'feed-f719dac8cc26c6c5', 'name': 'SSD Secure Disclosure', 'kind': 'rss', 'url': 'https://medium.com/feed/ssd-secure-disclosure'},
    {'id': 'feed-3398811f44671b6e', 'name': 'Tenable Tech Blog', 'kind': 'rss', 'url': 'https://medium.com/feed/tenable-techblog'},
    {'id': 'feed-bc4b487c6e675866', 'name': 'Symantec Threat Intelligence', 'kind': 'rss', 'url': 'https://medium.com/feed/threat-intel'},
    {'id': 'feed-88d9935a059e4d0f', 'name': 'Dr.Web Threat Alerts', 'kind': 'rss', 'url': 'https://news.drweb.ru/rss/get/?c=23'},
    {'id': 'feed-7bb5dc91e27122eb', 'name': 'PortSwigger Research', 'kind': 'rss', 'url': 'https://portswigger.net/research/rss'},
    {'id': 'feed-2b62007173a6f617', 'name': 'Google Project Zero', 'kind': 'rss', 'url': 'https://projectzero.google/feed.xml'},
    {'id': 'feed-52d931ce373f680f', 'name': 'ProjectDiscovery Nuclei Templates Releases', 'kind': 'rss', 'url': 'https://github.com/projectdiscovery/nuclei-templates/releases.atom'},
    {'id': 'feed-775d7028d700e914', 'name': 'Check Point Research', 'kind': 'rss', 'url': 'https://research.checkpoint.com/feed/'},
    {'id': 'feed-8c0e784bd01a3b1c', 'name': 'Schneier on Security', 'kind': 'rss', 'url': 'https://www.schneier.com/feed/atom/'},
    {'id': 'feed-8a3b81ee3853c884', 'name': 'Cisco Security Advisories', 'kind': 'rss', 'url': 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml'},
    {'id': 'feed-7ca81928e56a9cd5', 'name': 'Okta Security', 'kind': 'rss', 'url': 'https://sec.okta.com/rss.xml'},
    {'id': 'feed-7394e78beb2f2e9a', 'name': 'Security Affairs', 'kind': 'rss', 'url': 'https://securityaffairs.com/feed'},
    {'id': 'feed-01e4a85f1deaedcf', 'name': 'TechCrunch Security', 'kind': 'rss', 'url': 'https://techcrunch.com/category/security/feed/'},
    {'id': 'feed-4a349ec95eeb8804', 'name': 'The DFIR Report', 'kind': 'rss', 'url': 'https://thedfirreport.com/feed/'},
    {'id': 'feed-b53fef74a3c7e31c', 'name': 'Ubuntu Security Notices', 'kind': 'rss', 'url': 'https://ubuntu.com/security/notices/rss.xml'},
    {'id': 'feed-5feda8a4ed64053a', 'name': 'Unit 42', 'kind': 'rss', 'url': 'https://unit42.paloaltonetworks.com/feed/'},
    {'id': 'feed-ab1649b8e89fc56f', 'name': 'Anti-Malware.ru', 'kind': 'rss', 'url': 'https://www.anti-malware.ru/rss.xml'},
    {'id': 'feed-b9590a4fcf548600', 'name': 'Cobalt Blog', 'kind': 'rss', 'url': 'https://www.cobalt.io/blog/rss.xml'},
    {'id': 'feed-325145f0325b1d4a', 'name': 'Comss Security', 'kind': 'rss', 'url': 'https://www.comss.ru/rss.php'},
    {'id': 'feed-b23e5e82ae4e09ad', 'name': 'CSO Online', 'kind': 'rss', 'url': 'https://www.csoonline.com/feed/'},
    {'id': 'feed-a05c33a040436e2d', 'name': 'Dark Reading', 'kind': 'rss', 'url': 'https://www.darkreading.com/rss.xml'},
    {'id': 'feed-be342d056ff528b7', 'name': 'Debian Security Advisories', 'kind': 'rss', 'url': 'https://www.debian.org/security/dsa'},
    {'id': 'feed-e0db670cb97c01bb', 'name': 'Exploit Database', 'kind': 'rss', 'url': 'https://www.exploit-db.com/rss.xml'},
    {'id': 'feed-78ef10eb73401b34', 'name': 'HackRead', 'kind': 'rss', 'url': 'https://hackread.com/feed/'},
    {'id': 'feed-674fb947e30dbf9e', 'name': 'Help Net Security', 'kind': 'rss', 'url': 'https://www.helpnetsecurity.com/feed/'},
    {'id': 'feed-496803617126d09c', 'name': 'Infosecurity Magazine', 'kind': 'rss', 'url': 'https://www.infosecurity-magazine.com/rss/news/'},
    {'id': 'feed-4014f9ab2590dbd8', 'name': 'Kaspersky Blog', 'kind': 'rss', 'url': 'https://www.kaspersky.ru/blog/feed/'},
    {'id': 'feed-1fcd38c0441ed87c', 'name': 'KitPloit', 'kind': 'rss', 'url': 'https://kitploit.com/en/rss.xml'},
    {'id': 'feed-8a2e974b28c7ba7b', 'name': 'Malwarebytes Labs', 'kind': 'rss', 'url': 'https://www.malwarebytes.com/blog/feed/index.xml'},
    {'id': 'feed-87eee552ac27c4b2', 'name': 'Google Mandiant Threat Intelligence', 'kind': 'rss', 'url': 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v'},
    {'id': 'feed-d9797ada9149e396', 'name': 'Microsoft Security Blog', 'kind': 'rss', 'url': 'https://www.microsoft.com/en-us/security/blog/feed/'},
    {'id': 'feed-26b1b06dfad0aaa1', 'name': 'OpenNET Security', 'kind': 'rss', 'url': 'https://www.opennet.ru/opennews/opennews_sec.rss'},
    {'id': 'feed-03864289b497b55b', 'name': 'Palo Alto Networks Blog', 'kind': 'rss', 'url': 'https://www.paloaltonetworks.com/blog/feed/'},
    {'id': 'feed-eeb49163d938513e', 'name': 'Rapid7 Blog', 'kind': 'rss', 'url': 'https://www.rapid7.com/rss.xml'},
    {'id': 'feed-31fd93f467910ce5', 'name': 'Security Magazine Cybersecurity', 'kind': 'rss', 'url': 'https://www.securitymagazine.com/rss/topic/2236-cybersecurity'},
    {'id': 'feed-e7959df8a4fecf89', 'name': 'SecurityWeek', 'kind': 'rss', 'url': 'https://www.securityweek.com/feed/'},
    {'id': 'feed-cd1ae604774efdf8', 'name': 'SentinelOne Blog', 'kind': 'rss', 'url': 'https://www.sentinelone.com/blog/feed/'},
    {'id': 'feed-e46c54a79549cc8b', 'name': 'The Register Security', 'kind': 'rss', 'url': 'https://api.theregister.com/api/v1/article?orderBy=published&site_id=2&remapper=rss&query=tag:security'},
    {'id': 'feed-e1b9ef1a1ff970db', 'name': 'WIRED Security', 'kind': 'rss', 'url': 'https://www.wired.com/feed/category/security/latest/rss'},
    {'id': 'feed-d4674dd40af6e46b', 'name': 'ZDNET Security', 'kind': 'rss', 'url': 'https://www.zdnet.com/rss/news/'},
    {'id': 'feed-40780822b6acd62f', 'name': 'Zero Day Initiative Advisories', 'kind': 'rss', 'url': 'https://www.zerodayinitiative.com/rss/published/'},
    {'id': 'feed-62893c519a43397e', 'name': 'Хакер', 'kind': 'rss', 'url': 'https://xakep.ru/feed/'},
    {'id': 'feed-a003f93e91a7e68e', 'name': 'Техключи', 'kind': 'rss', 'url': 'https://xn--e1agfe6atq9c.xn--p1ai/rss/'},
    {'id': 'feed-94b44da475489c7a', 'name': 'CISA Advisories', 'kind': 'rss', 'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml'},
    {'id': 'feed-786ebbebc166c675', 'name': 'Dsec', 'kind': 'rss', 'url': 'https://dsec.ru/blog/rss/'},
    {'id': 'feed-6004885c0b7fbc23', 'name': 'Dr.Web', 'kind': 'rss', 'url': 'https://news.drweb.ru/rss/get/?c=5&lng=ru'},
    {'id': 'feed-372abc94a900cccf', 'name': 'Sophos News', 'kind': 'rss', 'url': 'https://www.sophos.com/en-us/blog/feed'},
    {'id': 'feed-e83e8d3e2365be8d', 'name': 'Avleonov', 'kind': 'rss', 'url': 'https://avleonov.com/feed/'},
    {'id': 'feed-a3728bc250627a3a', 'name': 'Threatpost', 'kind': 'rss', 'url': 'https://threatpost.com/feed/'},
    {'id': 'feed-2a104b44649cb84a', 'name': 'Sophos Blog (ранее Naked Security)', 'kind': 'rss', 'url': 'https://www.sophos.com/en-us/blog/feed'},
    {'id': 'feed-fb6a3ec633d94a60', 'name': 'SANS ISC Full', 'kind': 'rss', 'url': 'https://isc.sans.edu/rssfeed_full.xml'},
    {'id': 'feed-03d4af199c6e3394', 'name': 'Kitploit', 'kind': 'rss', 'url': 'https://kitploit.com/en/rss.xml'},
    {'id': 'feed-f5172a00e9671e52', 'name': 'Mandiant', 'kind': 'rss', 'url': 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/'},
    {'id': 'feed-896fc52901d1be6a', 'name': 'Intigriti', 'kind': 'rss', 'url': 'https://www.intigriti.com/blog/feed'},
    {'id': 'feed-70c14074448b1645', 'name': 'SecurityMagazine', 'kind': 'rss', 'url': 'https://www.securitymagazine.com/rss/topic/2236-cyber-security-news'},
    {'id': 'feed-e4163f13026c3567', 'name': 'The Register Security', 'kind': 'rss', 'url': 'https://api.theregister.com/api/v1/article?orderBy=published&site_id=2&remapper=rss&query=tag:security'},
    {'id': 'feed-729e366c4ab4b2b6', 'name': 'USENIX Security', 'kind': 'rss', 'url': 'https://www.usenix.org/blog/feed'},
    {'id': 'feed-5a677c9f3ade66f9', 'name': 'McAfee Labs', 'kind': 'rss', 'url': 'https://www.mcafee.com/blogs/feed/'},
    {'id': 'feed-671e3cb19c43de49', 'name': 'Elastic Security Labs', 'kind': 'rss', 'url': 'https://www.elastic.co/security-labs/rss/feed.xml'},
    {'id': 'feed-7c729533438f7762', 'name': 'Google Cloud Security', 'kind': 'rss', 'url': 'https://cloudblog.withgoogle.com/products/identity-security/rss/'},
    {'id': 'feed-47db0a7299e9be88', 'name': 'BDU FSTEC', 'kind': 'rss', 'url': 'https://bdu.fstec.ru/ubi/vul/rss'},
    {'id': 'feed-7a7d7bbda95ce6fa', 'name': 'BDU FSTEC (Опасные)', 'kind': 'rss', 'url': 'https://bdu.fstec.ru/ubi/vul/danger/rss'},
    {'id': 'feed-9b6b313173637440', 'name': 'BDU FSTEC (Инциденты)', 'kind': 'rss', 'url': 'https://bdu.fstec.ru/ubi/vul/incident/rss'},
    {'id': 'feed-02fecf91802e24a1', 'name': 'BDU FSTEC (Угрозы)', 'kind': 'rss', 'url': 'https://bdu.fstec.ru/ubi/threat/rss'},
    {'id': 'feed-4119cd0e71592b68', 'name': 'CERT-FR', 'kind': 'rss', 'url': 'https://cert.cyber.gouv.fr/feed/'},
    {'id': 'feed-66a4e13f83096a99', 'name': 'NCSC Switzerland (GovCERT)', 'kind': 'rss', 'url': 'https://www.newsd.admin.ch/newsd/feeds/rss?lang=en&org-nr=1101'},
    {'id': 'feed-6ca4ec1a9528aa13', 'name': 'Group-IB Blog', 'kind': 'rss', 'url': 'https://www.group-ib.com/blog/rss.xml'},
    {'id': 'feed-0a38b673280a59f7', 'name': 'WeLiveSecurity', 'kind': 'rss', 'url': 'https://www.welivesecurity.com/feed/'},
    {'id': 'feed-ed85ad123a96da65', 'name': 'JetBrains Blog', 'kind': 'rss', 'url': 'https://blog.jetbrains.com/feed/'},
    {'id': 'feed-fd694943bb333036', 'name': 'Citrix Security Bulletins', 'kind': 'rss', 'url': 'https://support.citrix.com/s/security-bulletins?language=en_US'},
    {'id': 'feed-f6881d7d2eab6186', 'name': 'CSO Online', 'kind': 'rss', 'url': 'https://www.csoonline.com/rss/'},
    {'id': 'feed-5dea443ab3ff0b42', 'name': 'Microsoft MSRC Update Guide', 'kind': 'rss', 'url': 'https://api.msrc.microsoft.com/update-guide/rss'},
    {'id': 'feed-f5cd398ad9aad659', 'name': 'Palo Alto Security Advisories', 'kind': 'rss', 'url': 'https://security.paloaltonetworks.com/rss.xml'},
    {'id': 'feed-3223901d28249716', 'name': 'Chrome Releases', 'kind': 'rss', 'url': 'https://feeds.feedburner.com/GoogleChromeReleases'},
    {'id': 'feed-f8b4329c6bc6084a', 'name': 'Kaspersky ICS CERT Advisories', 'kind': 'rss', 'url': 'https://ics-cert.kaspersky.ru/feed-advisories/'},
    {'id': 'feed-3a4d2dfaa4e568cb', 'name': 'CCCS Canada Alerts and Advisories', 'kind': 'rss', 'url': 'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en'},
    {'id': 'feed-61ae2d5f1f02d6ad', 'name': 'CERT/CC Vulnerability Notes', 'kind': 'rss', 'url': 'https://kb.cert.org/vuls/atomfeed/'},
    {'id': 'feed-8ea7252042476348', 'name': 'Ivanti Security Advisories', 'kind': 'rss', 'url': 'https://www.ivanti.com/blog/topics/security-advisory/rss'},
    {'id': 'sigmahq', 'name': 'SigmaHQ', 'kind': 'github', 'repository': 'SigmaHQ/sigma', 'ref': 'master', 'prefixes': ['rules/', 'rules-threat-hunting/', 'rules-emerging-threats/'], 'format': 'sigma', 'license_file': 'LICENSE'},
    {'id': 'elastic', 'name': 'Elastic Detection Rules', 'kind': 'github', 'repository': 'elastic/detection-rules', 'ref': 'main', 'prefixes': ['rules/'], 'format': 'elastic', 'license_file': 'LICENSE.txt'},
]



class CollectionLimit(RuntimeError):
    pass


class Budget:
    """One shared bound applies before rows are retained by any worker."""
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = 0
        self.count = 0

    def reserve(self, row, previous=None):
        size = len((json.dumps(row, ensure_ascii=False)+'\n').encode())
        if previous is not None:
            size -= len((json.dumps(previous, ensure_ascii=False)+'\n').encode())
        with self.lock:
            if self.bytes + max(0, size) > MAX_DATA or (previous is None and self.count >= MAX_ITEMS):
                raise CollectionLimit('Bundle limit reached; select fewer sources')
            self.bytes += max(0, size)
            if previous is None: self.count += 1

def public_url(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('HTTP(S) URL without credentials required')
    if any(ord(c) < 32 for c in value):
        raise ValueError('Invalid URL')
    return value


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_url(newurl)
        if req.full_url.startswith('https://') and not newurl.startswith('https://'):
            raise ValueError('HTTPS downgrade refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url, limit, timeout):
    public_url(url)
    opener = urllib.request.build_opener(Redirects())
    for attempt in range(2):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'STools-ThreatHunting/1', 'Accept-Encoding': 'identity'})
            with opener.open(request, timeout=timeout) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError('Source exceeds size limit')
            return data
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt: raise
            time.sleep(1)
    raise RuntimeError('Download failed')


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'nav', 'noscript', 'svg'):
            self.hidden += 1
        if tag in ('p', 'div', 'br', 'li', 'h1', 'h2', 'h3', 'article') and not self.hidden:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'nav', 'noscript', 'svg'):
            self.hidden = max(0, self.hidden - 1)
        if tag in ('p', 'div', 'li', 'article') and not self.hidden:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)


def plain(value):
    parser = PlainText()
    parser.feed(value)
    return '\n'.join(' '.join(line.split()) for line in ''.join(parser.parts).splitlines() if line.strip())


def date_value(value):
    if not value: return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip())
    except ValueError:
        try: parsed = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError): return None
    if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC).isoformat()


def local_tag(element):
    return element.tag.rsplit('}', 1)[-1]


def child_text(node, names):
    for name in names:
        for child in node:
            if local_tag(child) == name:
                return ''.join(child.itertext()).strip()
    return ''


def parse_feed(data, source, now, days, maximum, reserve=None):
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('XML entities are not allowed')
    root = ET.fromstring(data)
    if local_tag(root) not in ('rss', 'feed', 'RDF'):
        raise ValueError('Not an RSS/Atom feed')
    rows, seen = [], set()
    limited = False
    for entry in root.iter():
        if local_tag(entry) not in ('item', 'entry'): continue
        link = child_text(entry, ['link'])
        for child in entry:
            if local_tag(child) == 'link' and child.get('href') and child.get('rel', 'alternate') == 'alternate':
                link = child.get('href')
                break
        link = urllib.parse.urljoin(source['url'], link)
        try: public_url(link)
        except ValueError: continue
        external = child_text(entry, ['guid', 'id']) or link
        if len(external) > 1024: external = 'sha256:'+hashlib.sha256(external.encode()).hexdigest()
        if len(link) > 2048:
            limited = True
            continue
        if external in seen: continue
        seen.add(external)
        published = date_value(child_text(entry, ['published', 'pubDate', 'date', 'updated']))
        if days and published and dt.datetime.fromisoformat(published) < now - dt.timedelta(days=days): continue
        title = plain(child_text(entry, ['title'])) or link
        content = plain(child_text(entry, ['encoded', 'content', 'description', 'summary']))
        if len(rows) >= maximum:
            limited = True
            break
        truncated = len(content) > MAX_TEXT
        limited = limited or truncated
        row = {'source_id': source['id'], 'external_id': external[:1024], 'kind': 'news',
                     'title': title[:2000], 'url': link[:2048], 'text': content[:MAX_TEXT], 'format': 'article',
                     'published_at': published, 'technique_ids': sorted(set(TECHNIQUE.findall((title+'\n'+content).upper())))[:100],
                     'full_text': False}
        if reserve: reserve(row)
        rows.append(row)
    return rows, limited


def parse_rules(data, source, revision, reserve=None):
    rows, licenses = [], []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > 100_000 or sum(i.file_size for i in infos) > 512 * 1024 * 1024:
            raise ValueError('Repository exceeds archive limits')
        for info in infos:
            parts = info.filename.split('/')
            if len(parts) < 2 or '..' in parts or info.is_dir(): continue
            relative = '/'.join(parts[1:])
            if '/' not in relative and relative.upper().startswith(('LICENSE', 'NOTICE')) and info.file_size < 100_000:
                licenses.append(relative+'\n'+archive.read(info).decode('utf-8', errors='replace'))
            suffix = '.toml' if source['format'] == 'elastic' else '.yml'
            if not any(relative.startswith(prefix) for prefix in source['prefixes']) or not relative.endswith((suffix, '.yaml') if suffix == '.yml' else (suffix,)):
                continue
            if info.file_size > MAX_TEXT: raise ValueError('Rule exceeds text limit')
            raw = archive.read(info).decode('utf-8')
            title, published = relative, None
            if source['format'] == 'elastic':
                parsed = tomllib.loads(raw)
                title = parsed.get('rule', {}).get('name') or relative
                published = date_value(str(parsed.get('metadata', {}).get('creation_date', '')).replace('/', '-'))
            else:
                match = re.search(r'^title:\s*(.+)$', raw, re.MULTILINE)
                if match: title = match.group(1).strip('"\' ')
                match = re.search(r'^date:\s*([0-9/\-]+)', raw, re.MULTILINE)
                if match: published = date_value(match.group(1).replace('/', '-'))
            row = {'source_id': source['id'], 'external_id': relative, 'kind': 'rule', 'title': str(title)[:2000],
                         'url': f"https://github.com/{source['repository']}/blob/{revision}/{urllib.parse.quote(relative)}",
                         'text': raw, 'format': source['format'], 'published_at': published,
                         'technique_ids': sorted(set(TECHNIQUE.findall(raw.upper())))[:100], 'full_text': True}
            if reserve: reserve(row)
            rows.append(row)
            if len(rows) > MAX_ITEMS: raise ValueError('Too many rules')
    if not rows: raise ValueError('No rules found in repository')
    return rows, '\n\n'.join(licenses)[:100_000]


def collect_source(source, *, days, articles, maximum, timeout, fetcher, reserve=None):
    report = {'id': source['id'], 'name': source['name'], 'kind': 'news' if source['kind'] == 'rss' else 'rule',
              'url': source.get('url') or 'https://github.com/'+source['repository'], 'status': 'ok', 'items': 0}
    rows = []
    try:
        if source['kind'] == 'rss':
            rows, limited = parse_feed(fetcher(source['url'], 8*1024*1024, timeout), source, dt.datetime.now(dt.UTC), days, maximum, reserve)
            errors = 0
            if articles:
                for row in rows:
                    try:
                        html = fetcher(row['url'], 2*1024*1024, timeout).decode('utf-8', errors='replace')
                        if not re.search(r'<(?:html|article|body|!doctype html)\b', html, re.IGNORECASE):
                            raise ValueError('Not an HTML article')
                        body = plain(html)
                        if len(body) > len(row['text']):
                            changed = {**row, 'text': body[:MAX_TEXT], 'full_text': len(body) <= MAX_TEXT}
                            if reserve: reserve(changed, row)
                            row.update(changed)
                            limited = limited or len(body) > MAX_TEXT
                    except (OSError, ValueError): errors += 1
            if limited or errors:
                report.update(status='partial', error=f'Ограничения объёма: {limited}; ошибки загрузки статей: {errors}')
        elif source['kind'] == 'github':
            repository = source['repository']
            if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository): raise ValueError('Invalid repository')
            metadata = json.loads(fetcher(f"https://api.github.com/repos/{repository}/commits/{urllib.parse.quote(source['ref'], safe='')}", 2*1024*1024, timeout))
            revision = metadata['sha']
            if not re.fullmatch('[a-f0-9]{40}', revision): raise ValueError('Invalid commit')
            raw = fetcher(f'https://codeload.github.com/{repository}/zip/{revision}', 128*1024*1024, timeout)
            rows, license_text = parse_rules(raw, source, revision, reserve)
            report.update(revision=revision, license_text=license_text,
                          license_url=f"https://github.com/{repository}/blob/{revision}/{source.get('license_file', 'LICENSE')}")
        else: raise ValueError('Unsupported source kind')
        report['items'] = len(rows)
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        rows = []
        # Never print raw network exceptions (URLs/proxy credentials can be included).
        code = f'HTTP {exc.code}' if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
        report.update(status='error', items=0, error=f'Источник не загружен: {code}')
    return report, rows


def collect(sources, output, *, days=30, articles=False, maximum=200, timeout=20, workers=4, fetcher=fetch_url):
    if output.exists(): raise FileExistsError('Output already exists')
    if not sources or len(sources) > 300: raise ValueError('Choose 1–300 sources')
    for source in sources:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', source['id']) or not 1 <= len(source['name']) <= 200:
            raise ValueError('Invalid source ID/name')
        if source['kind'] == 'rss': public_url(source['url'])
        elif source['kind'] != 'github' or source.get('format') not in ('sigma', 'elastic'):
            raise ValueError('Unsupported source kind/format')
    ids = [s['id'] for s in sources]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate source IDs')
    reports, count, size = [], 0, 0
    digest = hashlib.sha256()
    budget = Budget()
    with tempfile.TemporaryFile() as stream:
        def job(source):
            return collect_source(source, days=days, articles=articles, maximum=maximum, timeout=timeout, fetcher=fetcher, reserve=budget.reserve)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            remaining = iter(sources)
            pending = {pool.submit(job, source) for source in [next(remaining, None) for _ in range(min(workers, len(sources)))] if source is not None}
            while pending:
                ready, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in ready:
                    report, rows = future.result()
                    next_source = next(remaining, None)
                    if next_source is not None: pending.add(pool.submit(job, next_source))
                    reports.append(report)
                    print(f"{report['id']}: {report['status']}, {len(rows)} материалов", flush=True)
                    for row in rows:
                        line = (json.dumps(row, ensure_ascii=False)+'\n').encode()
                        size += len(line); count += 1
                        if size > MAX_DATA or count > MAX_ITEMS: raise ValueError('Bundle limit reached; select fewer sources')
                        stream.write(line); digest.update(line)
        if not count and all(s['status'] == 'error' for s in reports): raise ValueError('All sources failed; archive not created')
        manifest = {'format': 'stools-th-intel', 'version': 1, 'generated_at': dt.datetime.now(dt.UTC).isoformat(),
                    'items_count': count, 'items_sha256': digest.hexdigest(), 'sources': reports}
        stream.seek(0)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix='.th-intel-', dir=output.parent, delete=False) as f: temporary = Path(f.name)
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False))
                with archive.open('items.jsonl', 'w') as target:
                    while chunk := stream.read(1024*1024): target.write(chunk)
            if temporary.stat().st_size > 64*1024*1024: raise ValueError('Compressed bundle exceeds 64 MiB')
            # Exclusive creation: never replace a prior collection.
            os.link(temporary, output)
        finally:
            if temporary: temporary.unlink(missing_ok=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, default=Path('threat-hunting-'+dt.datetime.now(dt.UTC).strftime('%Y%m%d-%H%M%S')+'.zip'))
    parser.add_argument('--sources', type=Path, help='JSON list replacing the built-in sources')
    parser.add_argument('--list-sources', action='store_true')
    parser.add_argument('--only', help='Comma-separated source IDs')
    parser.add_argument('--days', type=int, default=30, help='News age; 0 = every available feed item')
    parser.add_argument('--articles', action='store_true', help='Also fetch HTML article text (slower)')
    parser.add_argument('--max-per-source', type=int, default=200)
    parser.add_argument('--timeout', type=int, default=20)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if not 0 <= args.days <= 36500 or not 1 <= args.workers <= 8 or not 1 <= args.timeout <= 120 or not 1 <= args.max_per_source <= 2000:
        parser.error('Invalid limits: days 0–36500, workers 1–8, timeout 1–120, max-per-source 1–2000')
    try:
        sources = json.loads(args.sources.read_text()) if args.sources else DEFAULT_SOURCES
        if args.only:
            chosen = set(args.only.split(','))
            if chosen - {s['id'] for s in sources}: raise ValueError('Unknown source ID')
            sources = [s for s in sources if s['id'] in chosen]
        if args.list_sources:
            for source in sources: print(source['id']+'\t'+source['name'])
            return 0
        result = collect(sources, args.output, days=args.days, articles=args.articles,
                         maximum=args.max_per_source, timeout=args.timeout, workers=args.workers)
        partial = any(s['status'] != 'ok' for s in result['sources'])
        print(f"Архив: {args.output}; материалов: {result['items_count']}; сбор {'неполный' if partial else 'завершён'}")
        return 2 if partial else 0
    except (OSError, ValueError, KeyError, TypeError, CollectionLimit) as exc:
        print('Архив не создан: '+(str(exc) if isinstance(exc, (ValueError, CollectionLimit)) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
