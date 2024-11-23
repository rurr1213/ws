//
#include "WebSocket.h"

std::string WebSocketSecureServer::base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Important: avoid newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);

    return result;
}



void WebSocketSecureServer::onAccept(int clientSocket, const sockaddr_in& clientAddress) {
    TcpSocket::onAccept(clientSocket, clientAddress);  // Call the base class version if needed, or provide your custom behavior
    logInfo("onAccept");
    if (!performSSLHandshake(clientSocket)) {
        // Handle handshake failure;  closeClient() is likely already called in performSSLHandshake.
        logError("sslHand shake failed");
        return;
    }

    std::string requestHeaders;
    char buffer[256]; // A smaller buffer for reading lines
    int bytesRead;

    // Read headers line by line
    do {
        std::lock_guard<std::mutex> lock(sslMutex);
        bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytesRead <= 0) {
            // ... handle SSL read error ...
            SSL_free(ssl);
            closeClient();
            return;
        }
        buffer[bytesRead] = '\0';
        requestHeaders += buffer;
    } while (requestHeaders.find("\r\n\r\n") == std::string::npos); // Stop when headers end

    if (isWebSocketUpgradeRequest(requestHeaders) && // New function to check request headers
        upgradeToWebSocket(requestHeaders)) { // Pass the request to upgradeToWebSocket()
        handleWebSocketConnection();
    } else { // Handle WebSocket upgrade failure
        std::lock_guard<std::mutex> lock(sslMutex);
        SSL_free(ssl);
        ssl = nullptr;
        closeClient();
        return;
    }

    {
        std::lock_guard<std::mutex> lock(sslMutex);  // reacquire the mutex before freeing ssl
        SSL_free(ssl);
        ssl = nullptr;
    }
    closeClient();
}

bool WebSocketSecureServer::upgradeToWebSocket(const std::string& requestHeaders) {
    logInfo("upgradeToWebSocket()");

    // 1.  Get the Sec-WebSocket-Key from requestHeaders
    std::string key;
    size_t keyPos = requestHeaders.find("Sec-WebSocket-Key: ");
    if (keyPos != std::string::npos) {
        keyPos += 19; // Skip "Sec-WebSocket-Key: "
        size_t keyEnd = requestHeaders.find("\r\n", keyPos);
        if (keyEnd != std::string::npos) {
            key = requestHeaders.substr(keyPos, keyEnd - keyPos);
        }
    }

    if (key.empty()) {
        std::cerr << "Sec-WebSocket-Key header not found" << std::endl;
        return false;
    }

    // 2. Calculate the WebSocket Accept key
    std::string acceptKey = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // Magic string (RFC 6455)

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)acceptKey.c_str(), acceptKey.length(), digest);
    std::string encoded = base64_encode(digest, SHA_DIGEST_LENGTH);

    // 3. Construct the WebSocket upgrade response  (HTTP 101 Switching Protocols)
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + encoded + "\r\n\r\n";

    logInfo("sending response()");

    // 4. Send the response
    {
        std::lock_guard<std::mutex> lock(sslMutex);  // Acquire the mutex.
        int bytesWritten = SSL_write(ssl, response.c_str(), response.length());

        if (bytesWritten <= 0) {
            std::cerr << "Error writing WebSocket handshake response" << std::endl;
            return false; // Or handle error as needed.
        }
    }

    return true;
}

bool WebSocketSecureServer::readWebSocketFrame(WebSocketFrame& frame) {
    std::lock_guard<std::mutex> lock(sslMutex);  // Acquire mutex before using ssl
    logInfo("reading web socket frame()");

    // 1. Read the frame header (at least 2 bytes)
    uint8_t header[2];
    int bytesRead = SSL_read(ssl, header, 2);
    if (bytesRead <= 0) {
        // Handle error or connection close (return false)
        std::cerr << "Error reading WebSocket frame header" << std::endl;
        return false;
    }

    // 2. Parse the header
    frame.fin = (header[0] & 0x80) != 0;
    frame.opcode = static_cast<WebSocketOpcode>(header[0] & 0x0F);
    frame.masked = (header[1] & 0x80) != 0;
    frame.payload_length = header[1] & 0x7F;

    // 3. Read extended payload length if necessary
    if (frame.payload_length == 126) {
        uint16_t extendedLength;
        if (SSL_read(ssl, &extendedLength, 2) != 2) {
            std::cerr << "Error reading extended payload length" << std::endl; // Handle error
            return false;
        }
        frame.payload_length = ntohs(extendedLength); // Convert from network byte order
    } else if (frame.payload_length == 127) {
        uint64_t extendedLength;
        if (SSL_read(ssl, &extendedLength, 8) != 8) {
            std::cerr << "Error reading extended payload length" << std::endl; // Handle error
            return false;
        }
        frame.payload_length = be64toh(extendedLength); // Convert from big-endian network byte order to host byte order
    }


    // 4. Read masking key if masked (client-to-server frames MUST be masked)
    if (frame.masked) {
        uint8_t maskingKey[4];
        if (SSL_read(ssl, maskingKey, 4) != 4) {
            std::cerr << "Error reading masking key" << std::endl; // Handle error
            return false;
        }
        frame.masking_key.assign(maskingKey, maskingKey + 4);
    }


    // 5. Read the payload
    frame.payload.resize(frame.payload_length);  // Important! Resize the payload vector.
    uint64_t totalPayloadBytesRead = 0;
    while(totalPayloadBytesRead <  frame.payload_length) {
        bytesRead = SSL_read(ssl, frame.payload.data() + totalPayloadBytesRead, frame.payload_length - totalPayloadBytesRead);
        if (bytesRead <= 0) {
            std::cerr << "Error or connection closed while reading payload" << std::endl;// Handle error or connection close
            return false;
        }
        totalPayloadBytesRead += bytesRead;
    }

    // 6. Unmask the payload if masked
    if (frame.masked) {
        for (size_t i = 0; i < frame.payload.size(); ++i) {
            frame.payload[i] ^= frame.masking_key[i % 4];  // Unmasking operation
        }
    }


    return true;
}

bool WebSocketSecureServer::sendWebSocketFrame(const WebSocketFrame& frame) {
    std::lock_guard<std::mutex> lock(sslMutex);  // Acquire mutex before using ssl

    std::vector<uint8_t> buffer;  // Construct the entire frame first for efficiency

    // 1. Construct header (first 2 bytes)
    uint8_t header[2];
    header[0] = (frame.fin ? 0x80 : 0x00) | static_cast<uint8_t>(frame.opcode);
    header[1] = frame.masked ? 0x80 : 0x00;  // Server to client frames MUST NOT be masked


    // 2. Encode payload length in header (or extended payload length)
    size_t payloadLength = frame.payload.size();
    if (payloadLength <= 125) {
        header[1] |= payloadLength;
    } else if (payloadLength <= 65535) {
        header[1] |= 126;
        uint16_t extendedLength = htons(static_cast<uint16_t>(payloadLength));
        buffer.insert(buffer.end(), (uint8_t*)&extendedLength, (uint8_t*)&extendedLength + 2);
    } else {
        header[1] |= 127;
        uint64_t extendedLength = htobe64(payloadLength);
        buffer.insert(buffer.end(), (uint8_t*)&extendedLength, (uint8_t*)&extendedLength + 8);
    }

    buffer.insert(buffer.end(), header, header+2);

    // 4. Add the payload
    buffer.insert(buffer.end(), frame.payload.begin(), frame.payload.end());
    // 5. Send the frame
    long unsigned int totalBytesSent = 0;

    while(totalBytesSent < buffer.size()){
        int bytesSent = SSL_write(ssl, buffer.data() + totalBytesSent, buffer.size() - totalBytesSent);

        if (bytesSent <= 0) {
                std::cerr << "Error sending frame" << std::endl;
            return false; // handle error
        }
        totalBytesSent += bytesSent;
    }

    return true;
}

void WebSocketSecureServer::onReceiveBinaryData(const std::vector<uint8_t>& data, size_t length) {
    // Make a copy of the data if you need to store it beyond the scope of this function
    std::vector<uint8_t> dataCopy = data;  // Now dataCopy is safe to use.
    onReceiveBinaryData(dataCopy.data(), dataCopy.size());
}

bool WebSocketSecureServer::sendStringData(const std::string& textString) {
    std::lock_guard<std::mutex> lock(sslMutex); // Lock the mutex
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = OP_TEXT;
    frame.payload.assign(textString.begin(), textString.end()); // Convert string to vector<uint8_t>
    return sendWebSocketFrame(frame); // Corrected: Use member ssl
}

bool WebSocketSecureServer::sendBinaryData(const char* data, int length) {
    std::lock_guard<std::mutex> lock(sslMutex); // Lock the mutex
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = OP_BINARY;
    frame.payload.assign(data, data + length); // Convert char* to vector<uint8_t>
    return sendWebSocketFrame(frame);  // Corrected: Use member ssl
}

