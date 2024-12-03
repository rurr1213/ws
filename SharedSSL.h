#pragma once
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <openssl/ssl.h>

class SharedSSL {
public:
    SharedSSL() = default;

    void setSSL(SSL* ssl) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        ssl_ = std::shared_ptr<SSL>(ssl, SSL_free);
    }

    std::shared_ptr<SSL> getSSL() {  // Locking now inside getSSL()
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return ssl_;
    }

    void modifySSL(std::function<void(SSL*)> operation) {  // Locking now inside modifySSL()
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (ssl_) {
            operation(ssl_.get());
        }
    }
    bool valid() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return ssl_.get() != nullptr;
    }


private:
    std::shared_ptr<SSL> ssl_;
    std::shared_mutex mutex_;
};
