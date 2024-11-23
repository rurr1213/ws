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

    enum WebSocketOpcode : uint8_t {
        OP_CONTINUATION = 0x0,
        OP_TEXT = 0x1,  // Here's OP_TEXT
        OP_BINARY = 0x2,
        OP_CLOSE = 0x8,
        OP_PING = 0x9,
        OP_PONG = 0xA
    };

    struct WebSocketFrame {
        uint8_t opcode;
        bool fin;
        bool masked;
        uint64_t payload_length;
        std::vector<uint8_t> masking_key;
        std::vector<uint8_t> payload;
    };


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

    ~WebSocketSecureServer() {
        std::lock_guard<std::mutex> lock(sslMutex); // Protect ssl in destructor
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        SSL_CTX_free(ctx);
    }

    void onAccept(int clientSocket, const sockaddr_in& clientAddress);

    void startServer() {
        if (!listen()) {
            // Handle listen error
            return;
        }
        while (true) {
            accept(); // Use TcpSocket::accept()
        }
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

    bool upgradeToWebSocket(const std::string& requestHeaders);
    std::string base64_encode(const unsigned char *input, int length);

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

    bool readWebSocketFrame(WebSocketFrame& frame);

    bool sendWebSocketFrame(const WebSocketFrame& frame);



    virtual void onReceiveStringData(std::string& textString) {
    }

    virtual void onReceiveBinaryData(uint8_t *, std::size_t) {
    }

    void onReceiveBinaryData(const std::vector<uint8_t>& data, size_t length);
    bool sendStringData(const std::string& textString);
    bool sendBinaryData(const char* data, int length);

private:

};