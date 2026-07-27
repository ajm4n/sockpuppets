#!/usr/bin/env python3
import asyncio
import logging

from gui import start_gui
from gui.auth import operators
from server import SockPuppetsServer

logging.basicConfig(level=logging.INFO)


async def main():
    server = SockPuppetsServer(encryption_key=b"SOCKPUPPETS_KEY_2026")
    operators.add("lab", "lab-pass", must_change=False)
    await server.start_http_listener("0.0.0.0", 8088)
    await server.start_ws_listener("0.0.0.0", 8443)
    await server.start_dns_listener("0.0.0.0", 5353)
    await server.start_smb_listener("0.0.0.0", 4455)
    start_gui(server, 13337)
    logging.info("listeners and gui up")
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
