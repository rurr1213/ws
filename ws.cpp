#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "WebSocket.h"
#include "TcpSocket.h"
#include "Connection.h"


class MyTcpSocket : public TcpSocket {
public:
    MyTcpSocket(const std::string& ip, int port) : TcpSocket(ip, port) {}

    bool onAccept(int clientSocket, const sockaddr_in& clientAddress) override {
        std::cout << "Client connected from: " << inet_ntoa(clientAddress.sin_addr) << std::endl;
        // ... other actions after accepting a connection ...
        return true;
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
//std::string ip_address = "127.0.0.1";
std::string ip_address = "0.0.0.0";
int ws_port = 5056;

Logger thislogger;

class MyWebSocketSecureServer : public WebSocketSecureServer {
public:
    MyWebSocketSecureServer() : WebSocketSecureServer(keyFile, certFile, ip_address, ws_port, thislogger) {}

    void listenThreadFunc();
    void writeThreadFunc();
    void readThreadFunc();

    void onReceiveStringData(std::string& textString);

    virtual void onReceiveBinaryData(uint8_t *, std::size_t);
};

void MyWebSocketSecureServer::listenThreadFunc() {
    if (!listen()) { // Call listen ONLY once
        std::cout << "Listen failed"; // Handle the error appropriately
        return;
    }
    while (true) {
        bool stat = accept();
        if (stat) {
            std::cout << "Client connected\n";
        std::thread readThread(&MyWebSocketSecureServer::readThreadFunc, this);
        readThread.detach(); // Let the read thread manage its own lifetime
        } else {
            std::cout << "Accept failed"; // Handle the error appropriately
        }
    }
}


void MyWebSocketSecureServer::readThreadFunc() {
    bool exit = false;
    while (!exit) {
        if (!waitForReceiveEvent()) break;
        // Connection is active.  The loop continues as long as waitForReceiveEvent returns true.
        exit = !handleReceiveEvent();
    }
    // Connection closed or error. Clean up.
    std::cout << "Client disconnected\n";
}

void MyWebSocketSecureServer::onReceiveStringData(std::string& textString)
{
    std::vector<uint8_t> data(textString.begin(), textString.end());
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        connectionDataQueue.push(data);
    }
    queueCV.notify_one();  // Notify the write thread
}

void MyWebSocketSecureServer::onReceiveBinaryData(uint8_t *pdata, std::size_t length)
{
    std::vector<uint8_t> data(pdata, pdata + length); ;
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        connectionDataQueue.push(data);
    }
    queueCV.notify_one();  // Notify the write thread
}


void MyWebSocketSecureServer::writeThreadFunc() {
    while (true) {
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCV.wait(lock, [this] { return !connectionDataQueue.empty(); });  // Wait for data

        std::vector<uint8_t> data = connectionDataQueue.front();
        connectionDataQueue.pop();
        lock.unlock();  // Release lock before potential long write operation

        // Get the connection - simplified approach, needs improvement in real application.
        if (writeToConnection(data)) {
             // Data sent successfully
        } else {
            // Handle write error, might need to close connection.
        }
    }
}

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
        /*
        //MyTcpSocket wsserver("secondary.hyperkube.net", 5056);  // Listening on localhost
        MyTcpSocket wsserver("0.0.0.0", 5056);  // Listening on localhost
        if (wsserver.listen()) {
            while (true) {
                wsserver.accept();
                while(wsserver.waitAndReceive()){} // Keep receiving until client disconnects/error
            }
            wsserver.close();
        }
        */
        MyWebSocketSecureServer server;
        std::thread listenThread(&MyWebSocketSecureServer::listenThreadFunc, &server);
        std::thread writeThread(&MyWebSocketSecureServer::writeThreadFunc, &server);

        listenThread.join(); // Keep the server running
        writeThread.join();

//        MyWebSocketSecureServer tcpserver;
//        tcpserver.startServer();
    }
}
