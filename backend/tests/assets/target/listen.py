"""Принять соединение на 22 и 445 и закрыть, не отправляя данных."""
import asyncio


async def close(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()


async def main() -> None:
    servers = [await asyncio.start_server(close, "0.0.0.0", port) for port in (22, 445)]
    print("ready", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


asyncio.run(main())
