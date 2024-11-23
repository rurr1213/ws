#!/usr/bin/env python3

import asyncio
import websockets
import ssl

async def connect_websocket():
    #uri = "ws://127.0.0.1:5056"  # Replace with your server's URL
    #uri = "wss://agoralocal.mynetgear.com:5056"
    uri = "wss://secondary.hyperkube.net:5056"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # Or ssl.PROTOCOL_TLSv1_2 for older Python versions
    ssl_context.load_cert_chain("../wsserver/uWebSockets/misc/cert.pem", "../wsserver/uWebSockets/misc/key.pem")  # Provide paths to your cert and key

    async with websockets.connect(uri) as websocket:
        await websocket.send("Hello, WebSocket!")
        message = await websocket.recv()
        print(f"Received message: {message}")

asyncio.run(connect_websocket())