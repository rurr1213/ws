#include <functional>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h> // For SHA1
#include <openssl/bio.h> // For BIO functions
#include <openssl/evp.h> // For Base64 encoding/decoding
#include <mutex> // Include mutex header

#include "TcpSocket.h"

class Logger {
public:
    void add(std::string string) {
        std::cout << string << std::endl;
    }
};

class WebSocketSecureServer : TcpSocket {

    SSL_CTX *ctx;
    std::string key_file;
    std::string cert_file;
    SSL* ssl;  // Add ssl as a member
    std::mutex sslMutex;  // Mutex to protect ssl

    Logger logger;

    void logInfo(std::string string) {
        logger.add("INFO: " + string);
    }

    void logError(std::string string) {
        logger.add("ERROR: " + string);
    }

public:
    WebSocketSecureServer(
        const std::string key_file,
        const std::string cert_file,
        const std::string ipAddress, int port, Logger logger)
        : TcpSocket(ipAddress, port),
        key_file(key_file),
        cert_file(cert_file),
        ssl(nullptr),
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

    enum WebSocketOpcode : uint8_t {
        OP_CONTINUATION = 0x0,
        OP_TEXT = 0x1,  // Here's OP_TEXT
        OP_BINARY = 0x2,
        OP_CLOSE = 0x8,
        OP_PING = 0x9,
        OP_PONG = 0xA
    };

    private:
        struct WebSocketFrame {
            uint8_t opcode;
            bool fin;
            bool masked;
            uint64_t payload_length;
            std::vector<uint8_t> masking_key;
            std::vector<uint8_t> payload;
        };

    ~WebSocketSecureServer() {
        std::lock_guard<std::mutex> lock(sslMutex); // Protect ssl in destructor
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        SSL_CTX_free(ctx);
    }

    virtual void onAccept(int clientSocket, const sockaddr_in& clientAddress);

    void startServer() {
        if (!listen()) {
            // Handle listen error
            return;
        }
        while (true) {
            accept(); // Use TcpSocket::accept()
        }
    }

    void onAccept(int clientSocket, const sockaddr_in& clientAddress) override {
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

    bool performSSLHandshake(int clientSocket) {

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

        {
            std::lock_guard<std::mutex> lock(sslMutex);  // Acquire the mutex.
            ssl = _ssl;
        }

        return true;
    }

    bool isWebSocketUpgradeRequest(const std::string& requestHeaders) { // Check headers for WebSocket upgrade

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

    bool WebSocketSecureServer::upgradeToWebSocket(const std::string& requestHeaders) {

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

    static std::string base64_encode(const unsigned char *input, int length)
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

  void handleWebSocketConnection() {

        std::vector<uint8_t> fragmentedMessage; // To handle message fragmentation

        while (true) {  // Main WebSocket loop
            if (ssl == nullptr) {
                logError("Invalid ssl pointer in handleWebSocketConnection()");
                return;
            }

            WebSocketFrame frame;
            if (!readWebSocketFrame(frame)) {
                return; //  Return on error or close
            }


            if (!frame.fin) { /* Handle fragmented frames if needed.  This example treats each frame as a complete message. */ }


            // Process the frame based on its opcode
            switch (frame.opcode) {
                case OP_TEXT: {
                    std::string textMessage(frame.payload.begin(), frame.payload.end());
                    std::cout << "Received text message: " << textMessage << std::endl;
                    onReceiveStringData(textMessage);
                    break;
                }
                case OP_BINARY: {
                    std::cout << "Received binary message (" << frame.payload.size() << " bytes)" << std::endl;
                    onReceiveBinaryData(frame.payload, frame.payload.size());
                    // ... process binary message (e.g., save to file, etc.) ...
                    break;
                }
                case OP_PING: {
                     // Respond to ping with a pong
                    WebSocketFrame pongFrame;
                    pongFrame.opcode = OP_PONG;
                    pongFrame.fin = true;
                    pongFrame.payload = frame.payload; // Echo back the ping payload
                    sendWebSocketFrame(pongFrame);

                    break;
                }
                case OP_CLOSE: {
                    // Client initiated close.  Echo the close frame back and close the connection.
                    std::lock_guard<std::mutex> lock(sslMutex); // Protect sendWebSocketFrame()
                    WebSocketFrame closeFrame;
                    closeFrame.opcode = OP_CLOSE;
                    closeFrame.fin = true;
                    sendWebSocketFrame(closeFrame);
                    return;  // Exit the handleWebSocketConnection loop
                }
                default: {
                    // Handle other opcodes or unexpected frames.  You might want to close the connection here.
                    std::cerr << "Unexpected WebSocket opcode: " << (int)frame.opcode << std::endl;
                    return; // or handle the error as needed.
                }
            }
        }
    }

    bool WebSocketSecureServer::readWebSocketFrame(WebSocketFrame& frame) {
        std::lock_guard<std::mutex> lock(sslMutex);  // Acquire mutex before using ssl

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
        int totalPayloadBytesRead = 0;
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
        int totalBytesSent = 0;

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

    virtual void onReceiveStringData(std::string& textString);
    virtual void onReceiveBinaryData(uint8_t *, std::size_t);

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

};