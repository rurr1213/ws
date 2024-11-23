#pragma once
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

#include "tcp.h"

using namespace std;

class TcpStringTools
{
public:
    void createStringSize(const unique_ptr<string>& pdataString, const string command, const int dataSize);
};

class TcpStringServer {

public:
    TcpStringServer();
    bool runSever(void);
private:
    TcpStringTools tcpStringTools;
    unique_ptr<string> poutDataString = make_unique<string>();
    unique_ptr<string> pinDataString = make_unique<string>();
};

class TcpStringClient {
public:
    TcpStringClient(const string& _serverIpAddress, int _sendBytes);
    bool doShell(void);
    bool sendString(const string command, const int size = 0);
    bool receiveString(void);
private:
    int sendBytes = 0;
    const string& serverIpAddress;
    static const int SERVER_PORT = 5054;

    TcpStringTools tcpStringTools;

    unique_ptr<string> poutDataString = make_unique<string>();
    unique_ptr<string> pinDataString = make_unique<string>();
    CtcpString::Client client;

};


