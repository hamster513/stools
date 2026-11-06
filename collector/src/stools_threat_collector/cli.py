import argparse
import asyncio
import os
from pathlib import Path

import uvicorn
from telethon import TelegramClient

from .app import create_app
from .catalog import import_catalog
from .storage import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["serve", "token", "revoke", "backup", "restore", "telegram-login", "export", "catalog"])
    parser.add_argument("--data-dir", default=os.environ.get("COLLECTOR_DATA_DIR", "/data"))
    parser.add_argument("--name", default="stools")
    parser.add_argument("--output")
    parser.add_argument("--admin", action="store_true")
    parser.add_argument("--after", type=int, default=0)
    args = parser.parse_args()
    directory = Path(args.data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    store = Store(directory / "collector.db")
    if args.command == "serve":
        if not store.sources():
            import_catalog(store)
        uvicorn.run(create_app(store), host="0.0.0.0", port=8443,
                    ssl_certfile=os.environ.get("COLLECTOR_CERT_FILE", "/certs/server.crt"),
                    ssl_keyfile=os.environ.get("COLLECTOR_KEY_FILE", "/certs/server.key"), access_log=False)
    elif args.command == "catalog":
        print(f"Added {import_catalog(store)} sources; existing configuration preserved")
    elif args.command == "token":
        if not args.output:
            parser.error("--output file required")
        scopes = ["data:read", "sources:write"] if args.admin else ["data:read"]
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(store.create_token(args.name, scopes))
        print("Token saved to file")
    elif args.command == "revoke":
        store.revoke_token(args.name)
    elif args.command in ("backup", "restore", "export"):
        if not args.output:
            parser.error("--output file required")
        if args.command == "export":
            from .bundle import export_bundle
            export_bundle(store, args.after, Path(args.output))
        else:
            getattr(store, args.command)(Path(args.output))
    elif args.command == "telegram-login":
        from .adapters.telegram import credentials
        async def login():
            async with TelegramClient(*credentials()):
                print("Telegram session authorized")
        asyncio.run(login())


if __name__ == "__main__":
    main()
