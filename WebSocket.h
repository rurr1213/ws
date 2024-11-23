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

#include "TcpSocket.h"

class WebSocketSecureServer : TcpSocket {

    SSL_CTX *ctx;
    std::string key_file;
    std::string cert_file;

    WebSocketSecureServer(
        const std::string& key_file,
        const std::string& cert_file,
        const std::string& ipAddress, int port)
        : TcpSocket(ipAddress, port) {

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
      SSL_CTX_free(ctx);
    }

    virtual void onAccept(int clientSocket, const sockaddr_in& clientAddress);
    virtual void onReceive(const char* data, int length);
    bool send(const char* data, int length);

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
        SSL* ssl = performSSLHandshake(clientSocket);
        if (!ssl) {
            // Handle handshake failure;  closeClient() is likely already called in performSSLHandshake.
            return;
        }

        std::string requestHeaders;
        char buffer[256]; // A smaller buffer for reading lines
        int bytesRead;

        // Read headers line by line
        do {
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

        if (isWebSocketUpgradeRequest(requestHeaders)) {  // New function to check request headers
            if (upgradeToWebSocket(ssl, requestHeaders)) {  // Pass the request to upgradeToWebSocket()
                handleWebSocketConnection(ssl);     // New function to handle WebSocket communication
            } else {
                // Handle WebSocket upgrade failure
            }
        } else {
            // Handle regular HTTP requests or other traffic (if needed)
        }

        SSL_free(ssl);
        closeClient();
    }
private:
    SSL* performSSLHandshake(int clientSocket) {
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            perror("SSL_new failed");
            closeClient();  // Close the client socket on error
            return nullptr;
        }

        SSL_set_fd(ssl, clientSocket);

        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            char errBuf[256];
            ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
            std::cerr << "SSL_accept failed: " << errBuf << std::endl;
            SSL_free(ssl);     // Free the SSL object on error
            closeClient();     // Close the client socket on error
            return nullptr;
        }

        return ssl;
    }

    bool isWebSocketUpgradeRequest(const std::string& request);  // Check headers for WebSocket upgrade
    bool upgradeToWebSocket(SSL* ssl, const std::string& request); // Construct and send the 101 response
    bool upgradeToWebSocket(SSL* ssl) {
    }

  void handleWebSocketConnection(SSL* ssl) {
        while (true) {  // Main WebSocket loop
            WebSocketFrame frame;
            if (!readWebSocketFrame(ssl, frame)) {
                break; // Error or connection closed
            }

            if (!frame.fin) { /* Handle fragmented frames if needed.  This example treats each frame as a complete message. */ }


            // Process the frame based on its opcode
            switch (frame.opcode) {
                case OP_TEXT: {
                    std::string textMessage(frame.payload.begin(), frame.payload.end());
                    std::cout << "Received text message: " << textMessage << std::endl;
                    // ... process text message ...
                    break;
                }
                case OP_BINARY: {
                    std::cout << "Received binary message (" << frame.payload.size() << " bytes)" << std::endl;
                    // ... process binary message (e.g., save to file, etc.) ...
                    break;
                }
                case OP_PING: {
                     // Respond to ping with a pong
                    WebSocketFrame pongFrame;
                    pongFrame.opcode = OP_PONG;
                    pongFrame.fin = true;
                    pongFrame.payload = frame.payload; // Echo back the ping payload
                    sendWebSocketFrame(ssl, pongFrame);

                    break;
                }
                case OP_CLOSE: {
                    // Client initiated close.  Echo the close frame back and close the connection.
                    WebSocketFrame closeFrame;
                    closeFrame.opcode = OP_CLOSE;
                    closeFrame.fin = true;
                    sendWebSocketFrame(ssl, closeFrame);
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

    bool readWebSocketFrame(SSL* ssl, WebSocketFrame& frame) {
        // ... (Implement WebSocket frame parsing, including reading header, payload length, masking key, and payload)
    }

    bool sendWebSocketFrame(SSL* ssl, const WebSocketFrame& frame) {
        // ... (Implement WebSocket frame construction and sending, including writing header, payload length, masking key, and payload)
    }
};