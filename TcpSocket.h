#include <functional>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <iostream>


class TcpSocket {
public:
    TcpSocket(const std::string& ipAddress, int port) :
        ipAddress(ipAddress), port(port), listeningSocket(-1), clientSocket(-1) {}

    ~TcpSocket() {
        close();
    }

    bool listen() {
        listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listeningSocket < 0) {
            perror("socket creation failed");
            return false;
        }

        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);
        if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddress.sin_addr) <= 0) {
            perror("invalid address or address not supported");
            return false;
        }

        if (bind(listeningSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
            perror("bind failed");
            return false;
        }

        if (::listen(listeningSocket, 5) < 0) {
            perror("listen failed");
            return false;
        }

        return true;
    }


    void accept() {
          sockaddr_in clientAddress;
          socklen_t clientAddressLength = sizeof(clientAddress);
          clientSocket = ::accept(listeningSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);

          if (clientSocket < 0) {
              perror("accept failed");
               return;
          }
          onAccept(clientSocket, clientAddress);
    }


    virtual void onAccept(int clientSocket, const sockaddr_in& clientAddress) {
        //  Override in derived classes
        std::cout << "Client connected" << std::endl;

    }

    bool waitAndReceive() {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;  // 100ms timeout

        int activity = select(clientSocket + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
             perror("select error");
             return false;
        }

        if (FD_ISSET(clientSocket, &readfds)) {
            char buffer[1024] = {0};
            int valread = read(clientSocket, buffer, 1024);
            if (valread <=0) {
                // Connection closed or error.
                closeClient();
                return false;
            }
            onReceive(buffer, valread);
        }
        return true;
    }

    virtual void onReceive(const char* data, int length) {
         // Override this method to handle received data
         std::cout << "Received: " << std::string(data, length) << std::endl;
    }

    bool send(const char* data, int length) {
         int bytesSent = ::send(clientSocket, data, length, 0);
         if (bytesSent < 0) {
               perror("send failed");
               return false;
         }
         return true;
    }


    void closeClient() {
        if (clientSocket >= 0) {
            ::close(clientSocket);
            clientSocket = -1;
        }
    }

    void close() {
        closeClient();
        if (listeningSocket >= 0) {
            ::close(listeningSocket);
            listeningSocket = -1;
        }
    }



private:
    std::string ipAddress;
    int port;
    int listeningSocket;
    int clientSocket;
};
