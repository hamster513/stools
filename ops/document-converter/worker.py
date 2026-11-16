"""Disposable Office/MSG conversion worker; deploy with network_mode: none."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time

FORMATS = {'.doc': 'docx', '.rtf': 'docx', '.odt': 'docx', '.xls': 'xlsx', '.ods': 'xlsx',
           '.ppt': 'pptx', '.odp': 'pptx', '.msg': 'eml'}
LIMIT = 64 * 1024 * 1024


def one(request: Path) -> None:
    inputs = list(request.glob('input.*'))
    if len(inputs) != 1 or inputs[0].is_symlink() or inputs[0].stat().st_size > LIMIT:
        raise ValueError('invalid input')
    source = inputs[0]
    extension = FORMATS[source.suffix]
    result = request / ('result.' + extension)
    if source.suffix == '.msg':
        import extract_msg
        from email import policy
        with extract_msg.openMsg(str(source)) as msg:
            converted = msg.asEmailMessage().as_bytes(policy=policy.SMTP)
        if len(converted) > LIMIT:
            raise ValueError('output limit')
        result.write_bytes(converted)
    else:
        with tempfile.TemporaryDirectory(prefix='office-') as tmp:
            profile = Path(tmp) / 'profile'
            (profile / 'user').mkdir(parents=True)
            (profile / 'user/registrymodifications.xcu').write_text('''<?xml version="1.0"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry">
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Calc/Content/Update"><prop oor:name="Link" oor:op="fuse"><value>0</value></prop></item>
</oor:items>''')
            subprocess.run(['libreoffice', '-env:UserInstallation=' + profile.as_uri(), '--headless',
                            '--norestore', '--nodefault', '--nolockcheck', '--convert-to', extension,
                            '--outdir', tmp, str(source)], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            output = Path(tmp) / ('input.' + extension)
            if not output.is_file() or not 0 < output.stat().st_size <= LIMIT:
                raise ValueError('missing or oversized output')
            result.write_bytes(output.read_bytes())
    (request / 'done').touch()


def serve() -> None:
    queue = Path('/queue')
    while True:
        for request in sorted(queue.glob('job-*')):
            if request.is_symlink() or not request.is_dir():
                continue
            # Clean abandoned scratch data after API crashes; originals remain in job storage.
            if time.time() - request.stat().st_mtime > 600:
                shutil.rmtree(request, ignore_errors=True)
                continue
            if not (request / 'ready').is_file():
                continue
            if (request / 'done').exists() or (request / 'failed').exists():
                continue
            # A separate process bounds MSG parser and LibreOffice alike; kill the entire process group.
            process = subprocess.Popen([sys.executable, __file__, '--one', str(request)], start_new_session=True,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                process.wait(timeout=80)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            finally:
                # Launcher success/failure must not leave detached office children running.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if request.is_dir() and not (request / 'done').is_file():
                try:
                    (request / 'failed').touch()
                except FileNotFoundError:
                    pass  # the client timed out and removed this request
        time.sleep(0.2)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--one':
        one(Path(sys.argv[2]))
    else:
        serve()
