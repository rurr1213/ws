#!/usr/bin/env python3

import asyncio
import websockets
import ssl

async def handler(websocket):
    async for message in websocket:
        print(f"Received: {message}")
        await websocket.send(f"Echo: {message}")

async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("fullchain.pem", "privkey.pem") # Replace with your certificate paths

    async with websockets.serve(handler, "0.0.0.0", 5056, ssl=ssl_context): # Listen on all interfaces
        print("WebSocket server started on wss://0.0.0.0:5056")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())


