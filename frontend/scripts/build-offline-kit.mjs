import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeKit } from './write-kit.mjs';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = resolve(frontend, 'public/offline');
mkdirSync(destination, { recursive: true });
for (const name of ['ref_updates.py', 'ref_window.py']) {
  copyFileSync(resolve(frontend, '../backend/api/modules/vm/core', name), resolve(destination, name));
}
copyFileSync(resolve(frontend, 'public/siem/download-intel.py'), resolve(destination, 'intel_downloader.py'));
const collector = resolve(frontend, '../collector/src/stools_threat_collector');
copyFileSync(resolve(collector, 'adapters/telegram_public.py'), resolve(destination, 'telegram_public.py'));
const channels = JSON.parse(readFileSync(resolve(collector, 'sources.json'), 'utf8'))
  .filter(source => source.adapter === 'telegram' && source.telegram_mode === 'web')
  .map(source => ({ id: source.catalog_key, name: source.name, kind: 'telegram', url: source.url }));
writeFileSync(resolve(destination, 'telegram-sources.json'), JSON.stringify(channels, null, 2) + '\n');
const entries = ['README.md', 'download-stools.sh', 'download-stools.ps1', 'offline_download.py', 'offline_http.py', 'offline_sources.py', 'offline_telegram.py', 'telegram_public.py', 'telegram-sources.json', 'system-http.ps1', 'ref_updates.py', 'ref_window.py', 'intel_downloader.py'];
writeKit(destination, entries, resolve(destination, 'stools-download-kit.zip'));
console.log('Unified offline kit built: Linux + PowerShell + shared helpers');
