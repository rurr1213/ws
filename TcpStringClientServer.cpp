// netTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#ifdef _WIN64
#include "winLib/winLibFramework.h"
#include <conio.h>
#include "timing.h"
#else
#define _kbhit() true
#define _getch getchar
#define Sleep(ms) usleep(ms*1000)
#endif

#include <iostream>
#include <memory>
#include <stdio.h> 
//#include <getopt.h>

#include "TcpStringClientServer.h"

//CtcpString tcpString;

using namespace std;

void TcpStringTools::createStringSize(const unique_ptr<string>& pdataString, const string command, const int dataSize) {
    *pdataString = command + " ";
    int addSize = dataSize - (int)pdataString->size();
    addSize = addSize > 0 ? addSize : 0;
    pdataString->append((size_t)addSize, (char)'-');
}

// ---------------------------------------------------------------------------------

TcpStringServer::TcpStringServer() 
{
};

bool TcpStringServer::runSever(void)
{
    string peerSockAddr;
    int count = 0;
    std::cout << "Server Mode\n";
    #ifdef _WIN64
    DWORD processID = GetCurrentProcessId();
    cout << "ProcessId: " << processID << endl;
    #endif

    CtcpString::Server server;
    server.init("", 5054);
    bool exitTest = false;
    while (!exitTest) {
        server.listen();
        server.accept();
        peerSockAddr = server.getPeerSocket();
        server.sendString("CONNECTED");
        while (true) {
            if (server.isDataAvailable()) {
                if (!server.recvString(*pinDataString)) break;
                cout << ++count << ") ";

                if (pinDataString->find("ECHO") != string::npos) {
                    cout << "recvd ECHO: " << pinDataString->size();
                    cout << " | " << pinDataString->substr(0, 20) << "    ";
                    server.sendString(*pinDataString);
                    cout << "sent ECHO: " << pinDataString->size();
                    cout << " | " << pinDataString->substr(0, 20) << std::endl;
                }

                if (pinDataString->find("RECV") != string::npos) {
                    cout << "recvd RECV: " << pinDataString->size();
                    cout << " | " << pinDataString->substr(0, 20) << "    " << endl;
                }

                if (pinDataString->find("SEND") != string::npos) {
                    size_t pos = pinDataString->find("SEND");
                    pos += 4;
                    size_t posComma = pinDataString->find(",");
                    if (posComma != string::npos) {
                        string valueString = pinDataString->substr(pos, (posComma - pos));
                        int sendSize = std::stoi(valueString);
                        tcpStringTools.createStringSize(poutDataString, "SEND", sendSize);
                        server.sendString(*poutDataString);
                        cout << "recvd SEND, sent " << poutDataString->size();
                        cout << " | " << poutDataString->substr(0, 20) << std::endl;
                    }
                }

                if (pinDataString->find("EXIT") != string::npos) {
                    cout << "recvd EXIT\n";
                    exitTest = true;
                }
            }
        }
    }
    server.deinit();
    return true;
};


TcpStringClient::TcpStringClient(const string& _serverIpAddress, int _sendBytes)
    : sendBytes{ _sendBytes }, 
    serverIpAddress{ _serverIpAddress }
{};

bool TcpStringClient::doShell(void)
{
    #ifdef _WIN64
    CTimer timer;
    #endif

    client.init();

    if (!client.connect(serverIpAddress, SERVER_PORT)) {
        std::cout << "Server not available\n";
        return false;
    }
    bool exitNow = false;

    std::cout << "Client Interactive Mode\n";
    cout << "q/ESC - quit, x - exit, e - echo, s - send, r - recv, l - echo loop\n";
    #ifdef _WIN64
    DWORD processID = GetCurrentProcessId();
    cout << "ProcessId: " << processID << endl;
    #endif

    while (!exitNow) {
        if (_kbhit()) {
            char ch = _getch();
            switch (ch) {
            case 27:
            case 'q':
                exitNow = true;
                break;
            case 's':
                cout << "Sent ";
                sendString("RECV", sendBytes);
                break;
            case 'r':
                {
                    cout << "Sent ";
                    string command = "SEND ";
                    command += to_string(sendBytes) + ",";
                    sendString(command);
                }
                break;
            case 'e':
                {
                    cout << "Sent ";
                    sendString("ECHO", sendBytes);
                }
                break;
            case 'x':
                {
                    exitNow = true;
                    sendString("EXIT");
                    Sleep(1000);
                }
                break;
            case 'l':
                {
                    while (true) {
                        sendString("ECHO", sendBytes);
                        Sleep(200);
                        if (!receiveString()) break;
                    }
                }
                break;
            }
        }
        Sleep(100);
        if (!receiveString()) break;
    }

    client.deinit();

    return true;
}
bool TcpStringClient::sendString(const string command, const int size) {
    tcpStringTools.createStringSize(poutDataString, command, size);
    client.sendString(*poutDataString);
    std::cout << command << " | sent :" << poutDataString->size() << std::endl;
    return true;
}

bool TcpStringClient::receiveString(void) {
    if (client.isDataAvailable()) {
        if (!client.recvString(*pinDataString)) return false;
        std::cout << "Recvd :" << pinDataString->size() << " | ";
        std::cout << "data: " << pinDataString->substr(0, 20) << std::endl;
    }
    return true;
}


