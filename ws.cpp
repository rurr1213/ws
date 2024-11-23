#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "TcpSocket.h"

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
        if (received == "exit") {  // Example: close connection on "exit" command
            closeClient();
        }
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
        MyTcpSocket server("127.0.0.1", 5056);  // Listening on localhost
        if (server.listen()) {
            while (true) {
                server.accept();
                while(server.waitAndReceive()){} // Keep receiving until client disconnects/error
            }
            server.close();
        }
    }
}
