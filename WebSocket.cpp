//
#include "WebSocket.h"

WebSocketSecureServer::WebSocketSecureServer(
    const std::string key_file,
    const std::string cert_file,
    const std::string ipAddress, int port, Logger logger)
    : TcpSocket(ipAddress, port),
    key_file(key_file),
    cert_file(cert_file),
    logger(logger)
    {  // Correctly initialize key_file and cert_file

    ctx = SSL_CTX_new(TLS_server_method()); // Use TLSv1.2 or later

    if (!ctx) {
        perror("SSL_CTX_new failed");
        // Or handle the error appropriately - potentially throw an exception.  This is the shared object, so it's serious if this fails.
    }


    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file failed");
        SSL_CTX_free(ctx);
        // Or handle the error appropriately - potentially throw an exception
    }


        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        perror("SSL_CTX_use_PrivateKey_file failed");
        SSL_CTX_free(ctx);
        // Or handle the error appropriately - potentially throw an exception
    }
}

WebSocketSecureServer::~WebSocketSecureServer() {
    SSL_CTX_free(ctx);
}

void WebSocketSecureServer::startServer() {
    while (true) {
        if (!listen()) {
            // Handle listen error
            return;
        }
        accept(); // Use TcpSocket::accept()
    }
}

bool WebSocketSecureServer::performSSLHandshake(int clientSocket) {

    SSL *_ssl = SSL_new(ctx);
    if (!_ssl) {
        perror("SSL_new failed");
        closeClient();  // Close the client socket on error
        return false;
    }

    SSL_set_fd(_ssl, clientSocket);

    int ret = SSL_accept(_ssl);
    if (ret <= 0) {
        char errBuf[256];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        std::cerr << "SSL_accept failed: " << errBuf << std::endl;
        SSL_free(_ssl);     // Free the SSL object on error
        closeClient();     // Close the client socket on error
        return false;
    }

    connection.setSSL(_ssl);

    return true;
}

bool WebSocketSecureServer::isWebSocketUpgradeRequest(const std::string& requestHeaders) { // Check headers for WebSocket upgrade

    // Check for key headers indicating a WebSocket upgrade request
    bool upgradeHeaderPresent = (requestHeaders.find("Upgrade: websocket") != std::string::npos);
    bool connectionHeaderPresent = (requestHeaders.find("Connection: Upgrade") != std::string::npos);
    bool keyHeaderPresent = (requestHeaders.find("Sec-WebSocket-Key:") != std::string::npos);
    bool versionHeaderPresent = (requestHeaders.find("Sec-WebSocket-Version: 13") != std::string::npos); // Check for version 13 or later as needed.

    if (upgradeHeaderPresent && connectionHeaderPresent && keyHeaderPresent && versionHeaderPresent) {
        return true; // All required headers present
    }

    return false; // Not a WebSocket upgrade request
};

bool WebSocketSecureServer::handleWebSocketConnection() {
    fd_set readfds;
    timeval timeout;

    while (true) {  // Main WebSocket loop
        if (!connection.valid()) {
            logError("Invalid ssl pointer in handleWebSocketConnection()");
            return false;
        }

        // Setup select()
        FD_ZERO(&readfds);
        FD_SET(connection.getSocket(), &readfds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // Set timeout (e.g., 100ms)

        int activity = select(connection.getSocket() + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select error");
            logError("Select() returned error");
            return false;
        } else if (activity == 0) {
            continue; // Timeout; No data to read yet.
        }

        // Read and process the frame
        WebSocketFrame frame;
        if (!readWebSocketFrame(frame)) {
            logInfo("Closing client connection (readWebSocketFrame failed)");
            return false; // Return false to indicate connection closed
        }

        // Handle fragmentation
        if (frame.opcode == OP_TEXT || frame.opcode == OP_BINARY) {
            if (!frame.fin) { // Not the final frame
                std::lock_guard<std::mutex> lock(connection.fragmentedMutex); // Lock for fragment access
                connection.fragmentedMessage.insert(connection.fragmentedMessage.end(), frame.payload.begin(), frame.payload.end());
                continue; // Get more fragments
            } else { // Final frame (or single-frame message)
                std::lock_guard<std::mutex> lock(connection.fragmentedMutex); // Lock for fragment access
                if (!connection.fragmentedMessage.empty()) {
                    connection.fragmentedMessage.insert(connection.fragmentedMessage.end(), frame.payload.begin(), frame.payload.end());
                    frame.payload = connection.fragmentedMessage; // Use the combined message
                    connection.fragmentedMessage.clear(); // Clear for the next message
                }
            }
        } else if (!connection.fragmentedMessage.empty()) { // Discard fragments on control frame.
            std::lock_guard<std::mutex> lock(connection.fragmentedMutex); // Lock for fragment access
            connection.fragmentedMessage.clear();
        }


        // Process the complete frame based on its opcode
        switch (frame.opcode) {
            case OP_TEXT: {
                std::string textMessage(frame.payload.begin(), frame.payload.end());
                std::cout << "Received text message: " << textMessage << std::endl;
                onReceiveStringData(textMessage);
                break;
            }
            case OP_BINARY: {
                std::cout << "Received binary message (" << frame.payload.size() << " bytes)" << std::endl;
                onReceiveBinaryData(frame.payload.data(), frame.payload.size());
                break;
            }
            case OP_PING: {
                WebSocketFrame pongFrame;
                pongFrame.opcode = OP_PONG;
                pongFrame.fin = true;
                pongFrame.payload = frame.payload; // Echo back the ping payload
                sendWebSocketFrame(pongFrame);
                break;
            }
            case OP_CLOSE: {
                WebSocketFrame closeFrame;
                closeFrame.opcode = OP_CLOSE;
                closeFrame.fin = true;
                sendWebSocketFrame(closeFrame);
                closeClient();  // Close the client connection
                return false;  // Indicate connection closed
            }
            default: {
                std::cerr << "Unexpected WebSocket opcode: " << (int)frame.opcode << std::endl;
                closeClient(); // Close on unexpected opcode
                return false;
            }
        }
    } // End of main while loop
}

void WebSocketSecureServer::onReceiveStringData(std::string& textString) {
}

void WebSocketSecureServer::onReceiveBinaryData(uint8_t *, std::size_t) {
}


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



bool WebSocketSecureServer::onAccept(int clientSocket, const sockaddr_in& clientAddress) {
    TcpSocket::onAccept(clientSocket, clientAddress);  // Call the base class version if needed, or provide your custom behavior
    connection.setSocket(clientSocket); 
    logInfo("onAccept");
    if (!performSSLHandshake(clientSocket)) {
        // Handle handshake failure;  closeClient() is likely already called in performSSLHandshake.
        logError("sslHand shake failed");
        return false;
    }

    std::string requestHeaders;
    char buffer[256]; // A smaller buffer for reading lines
    int bytesRead;

    // Read headers line by line
    do {
        auto ssl = connection.getSSL(); // Get the shared_ptr
        if (!ssl) return false;

        bytesRead = SSL_read(ssl.get(), buffer, sizeof(buffer) - 1);
        if (bytesRead <= 0) {
            closeClient();
            return false;
        }
        buffer[bytesRead] = '\0';
        requestHeaders += buffer;
    } while (requestHeaders.find("\r\n\r\n") == std::string::npos); // Stop when headers end

    if (isWebSocketUpgradeRequest(requestHeaders) && // New function to check request headers
        upgradeToWebSocket(requestHeaders)) { // Pass the request to upgradeToWebSocket()
        return true;
    } else { // Handle WebSocket upgrade failure
        auto ssl = connection.getSSL(); // Get the shared_ptr
        if (!ssl) return false;
        SSL_free(ssl.get());
        closeClient();
        return false;
    }
    return true;
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
        auto ssl = connection.getSSL(); // Get the shared_ptr
        if (!ssl) return false;
        int bytesWritten = SSL_write(ssl.get(), response.c_str(), response.length());

        if (bytesWritten <= 0) {
            std::cerr << "Error writing WebSocket handshake response" << std::endl;
            return false; // Or handle error as needed.
        }
    }

    return true;
}

bool WebSocketSecureServer::readWebSocketFrame(WebSocketFrame& frame) {
    auto ssl = connection.getSSL(); // Get the shared_ptr
    if (!ssl) return false;

    logInfo("reading web socket frame()");

    // 1. Read the frame header (at least 2 bytes)
    uint8_t header[2];
    int bytesRead = SSL_read(ssl.get(), header, 2);
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
        if (SSL_read(ssl.get(), &extendedLength, 2) != 2) {
            std::cerr << "Error reading extended payload length" << std::endl; // Handle error
            return false;
        }
        frame.payload_length = ntohs(extendedLength); // Convert from network byte order
    } else if (frame.payload_length == 127) {
        uint64_t extendedLength;
        if (SSL_read(ssl.get(), &extendedLength, 8) != 8) {
            std::cerr << "Error reading extended payload length" << std::endl; // Handle error
            return false;
        }
        frame.payload_length = be64toh(extendedLength); // Convert from big-endian network byte order to host byte order
    }


    // 4. Read masking key if masked (client-to-server frames MUST be masked)
    if (frame.masked) {
        uint8_t maskingKey[4];
        if (SSL_read(ssl.get(), maskingKey, 4) != 4) {
            std::cerr << "Error reading masking key" << std::endl; // Handle error
            return false;
        }
        frame.masking_key.assign(maskingKey, maskingKey + 4);
    }


    // 5. Read the payload
    frame.payload.resize(frame.payload_length);  // Important! Resize the payload vector.
    uint64_t totalPayloadBytesRead = 0;
    while(totalPayloadBytesRead <  frame.payload_length) {
        bytesRead = SSL_read(ssl.get(), frame.payload.data() + totalPayloadBytesRead, frame.payload_length - totalPayloadBytesRead);
        if (bytesRead <= 0) {
            std::cerr << "Error or connection closed while reading payload" << std::endl;// Handle error or connection close
            logError("Error or connection closed while reading payload");
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
    auto ssl = connection.getSSL(); // Get the shared_ptr
    if (!ssl) return false;

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
        int bytesSent = SSL_write(ssl.get(), buffer.data() + totalBytesSent, buffer.size() - totalBytesSent);

        if (bytesSent <= 0) {
            std::cerr << "Error sending frame" << std::endl;
            logError("Error sending frame");
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
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = OP_TEXT;
    frame.payload.assign(textString.begin(), textString.end()); // Convert string to vector<uint8_t>
    return sendWebSocketFrame(frame); // Corrected: Use member ssl
}

bool WebSocketSecureServer::sendBinaryData(const char* data, int length) {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = OP_BINARY;
    frame.payload.assign(data, data + length); // Convert char* to vector<uint8_t>
    return sendWebSocketFrame(frame);  // Corrected: Use member ssl
}

Connection* WebSocketSecureServer::acceptConnection() {
    int clientSocket;
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLength = sizeof(clientAddress);

    clientSocket = ::accept(listeningSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (clientSocket < 0) {
        perror("accept failed");
        return nullptr;
    }
    TcpSocket::onAccept(clientSocket, clientAddress);
    if (!performSSLHandshake(clientSocket)) {
        logError("sslHand shake failed");
        closeClient();  // Ensure client socket is closed on handshake failure.
        return nullptr; // Return nullptr to indicate failure.
    }
    return &connection;
}


bool WebSocketSecureServer::readFromConnection(Connection* connection, std::vector<uint8_t>& data) {
    WebSocketFrame frame;
    { // Scope for mutex lock
        //std::lock_guard<std::mutex> lock(connection->sslMutex); // Acquire the connection's mutex
        if (!readWebSocketFrame(frame)) {
            // handle read error as needed, might involve closing the connection from the calling function.
            return false;
        }
    }

    data = frame.payload; // Return payload directly (avoid extra copy)
    return true;
}


bool WebSocketSecureServer::writeToConnection(const std::vector<uint8_t>& data) {
    WebSocketFrame frame = createFrame(data, OP_TEXT); // or OP_BINARY as needed
    //std::lock_guard<std::mutex> lock(connection->sslMutex); // Acquire the connection's mutex
    return sendWebSocketFrame(frame);
}

WebSocketSecureServer::WebSocketFrame WebSocketSecureServer::createFrame(const std::vector<uint8_t>& data, WebSocketOpcode opcode) {
    WebSocketFrame frame;
    frame.fin = true;
    frame.opcode = opcode;
    frame.payload = data; // No need to copy if data is already a vector<uint8_t>
    return frame;
}

