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
        const std::string ipAddress, int port, Logger logger);

    ~WebSocketSecureServer();

    void onAccept(int clientSocket, const sockaddr_in& clientAddress);

    void startServer();

    bool performSSLHandshake(int clientSocket);

    bool isWebSocketUpgradeRequest(const std::string& requestHeaders);

    bool upgradeToWebSocket(const std::string& requestHeaders);

    std::string base64_encode(const unsigned char *input, int length);

    void handleWebSocketConnection();

    bool readWebSocketFrame(WebSocketFrame& frame);

    bool sendWebSocketFrame(const WebSocketFrame& frame);

    virtual void onReceiveStringData(std::string& textString);

    virtual void onReceiveBinaryData(uint8_t *, std::size_t);

    void onReceiveBinaryData(const std::vector<uint8_t>& data, size_t length);

    bool sendStringData(const std::string& textString);

    bool sendBinaryData(const char* data, int length);

private:

};