#pragma once
#include "SharedSSL.h"

class Connection {
public:
    Connection() = default;  // Keep default constructor
    ~Connection() = default;

    int getSocket() const { return socket_; } // Add getSocket() method
    void setSocket(int sock) { socket_ = sock; } // Add setSocket

    std::shared_ptr<SSL> getSSL() {  // No changes here
        return sharedSSL_.getSSL();  // SharedSSL handles locking
    }

    void close() {
        sharedSSL_.modifySSL([](SSL* ssl) {
            if (ssl) {
                SSL_shutdown(ssl);
            }
        });
    }
    bool valid() { // No changes here, but implementation now in SharedSSL.
        return sharedSSL_.valid();
    }
    void setSSL(SSL *_ssl) {  // No changes here
        sharedSSL_.setSSL(_ssl);
    }

    std::mutex fragmentedMutex;        // Mutex to protect fragmented message access.
    std::vector<uint8_t> fragmentedMessage; // Store fragmented messages.

private:
    SharedSSL sharedSSL_;
    int socket_ = -1; 
};
