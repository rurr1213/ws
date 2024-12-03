#pragma once
#include "SharedSSL.h"

class Connection {
public:
    Connection() = default;  // Keep default constructor
    ~Connection() = default;


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


private:
    SharedSSL sharedSSL_;
};
