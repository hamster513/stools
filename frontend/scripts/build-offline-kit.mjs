import { copyFileSync, mkdirSync } from 'node:fs';
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
const entries = ['README.md', 'download-stools.sh', 'download-stools.ps1', 'offline_download.py', 'offline_http.py', 'offline_sources.py', 'system-http.ps1', 'ref_updates.py', 'ref_window.py', 'intel_downloader.py'];
writeKit(destination, entries, resolve(destination, 'stools-download-kit.zip'));
console.log('Unified offline kit built: Linux + PowerShell + shared helpers');
