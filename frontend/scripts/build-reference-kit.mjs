import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeKit } from './write-kit.mjs';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = resolve(frontend, 'public/vm');
mkdirSync(destination, { recursive: true });
copyFileSync(resolve(frontend, '../backend/api/modules/vm/core/ref_updates.py'), resolve(destination, 'ref_updates.py'));
writeKit(destination, ['download-references.sh', 'download-references.ps1', 'ref_updates.py'], resolve(destination, 'reference-update-scripts.zip'));
console.log('Reference update kit built');
