#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "WebSocket.h"

class MyTcpSocket : public TcpSocket {
public:
    MyTcpSocket(const std::string& ip, int port) : TcpSocket(ip, port) {}

    void onAccept(int clientSocket, const sockaddr_in& clientAddress) override {
        std::cout << "Client connected from: " << inet_ntoa(clientAddress.sin_addr) << std::endl;
        // ... other actions after accepting a connection ...
    }

    void onReceive(const char* data, int length) override {
        std::string received(data, length);
        std::cout << "Received: " << received << std::endl;
        // ... process the received data ...
        std::string response = received;
        send(response.c_str(), response.length());
        if (received == "exit") {  // Example: close connection on "exit" command
            closeClient();
        }
    }
};


std::string keyFile = "privkey.pem";
std::string certFile = "fullchain.pem";
std::string ip_address = "127.0.0.1";
int ws_port = 5056;

Logger thislogger;

class MyWebSocketSecureServer : public WebSocketSecureServer {
public:
    MyWebSocketSecureServer() : WebSocketSecureServer(keyFile, certFile, ip_address, ws_port, thislogger) {}

    void onReceiveStringData(std::string& textString) {
        std::cout << "RecT: " << textString << std::endl;
    }

    void onReceiveBinaryData(uint8_t *, std::size_t) {
        std::cout << "RecB: " << std::endl;
    }
};

int main(int argc, char **argv)
{
    int c;
    bool client = false;

    printf("ws\n");

    opterr = 0;

    while ((c = getopt (argc, argv, "c:")) != -1) {
        switch (c) {
        case 'h':
            fprintf (stdout,"-c <configFileName");
            break;
        case '?':
            if (optopt == 'c') {
                printf("client\n");
                client = true;
            }
            break;
        default:
            abort ();
        }

    }


    if (client==true) {
    } else {
        MyTcpSocket wsserver("127.0.0.1", 5056);  // Listening on localhost
        if (wsserver.listen()) {
            while (true) {
                wsserver.accept();
                while(wsserver.waitAndReceive()){} // Keep receiving until client disconnects/error
            }
            wsserver.close();
        }
        /*
        MyWebSocketSecureServer tcpserver;
        tcpserver.startServer();
        */
    }
}
