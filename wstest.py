#!/usr/bin/env python3

import asyncio
import websockets
import ssl

async def connect_websocket():
    uri = "wss://127.0.0.1:5056"

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # Start with TLS client

    # Try older protocol versions. ORDER MATTERS! Start with most preferred and go down
    try:
        ssl_context.options |= ssl.OP_NO_TLSv1_3  # Disable TLSv1.3 first if it's the default
        ssl_context.options |= ssl.OP_NO_TLSv1_2  # Disable TLSv1.2 if still doesn't work
        ssl_context.options |= ssl.OP_NO_TLSv1_1 # Optionally disable TLSv1.1
        ssl_context.options |= ssl.OP_NO_TLSv1   # Lastly, optionally disable TLSv1


        ssl_context.load_cert_chain("../wsserver/uWebSockets/misc/cert.pem", "../wsserver/uWebSockets/misc/key.pem")

        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            await websocket.send("Hello, WebSocket!")
            message = await websocket.recv()
            print(f"Received message: {message}")

    except Exception as e:
        print(f"Connection error: {e}")

asyncio.run(connect_websocket())