
#ifndef _WIN64
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <iostream>     // std::cout
#include <fstream>      // std::ifstream

#include <tuple>
#include <list>
#else
#include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0
#endif

#include "tcp.h"

#include <string>

using namespace std;

bool Ctcp::Common::WSAStartupInitialized = false;

Ctcp::Ctcp()
{
}

// --------------------------------------------

Ctcp::Common::Common() :
    serv_addr{ 0 },
    port{ 0 },
    serv_addr_string{},
    hsocket{ INVALID_SOCKET },
    read_fd_set{0},
    timeoutZero{ 0 }
{
}

Ctcp::Common::Common(const Ctcp::Common& _other) :
    serv_addr{ _other.serv_addr },
    port{ _other.port },
    serv_addr_string{ _other.serv_addr_string },
    hsocket{ _other.hsocket },
    read_fd_set{ _other.read_fd_set },
    timeoutZero{ _other.timeoutZero }
{
}

Ctcp::Common::~Common()
{
}

bool Ctcp::Common::init(bool _initWSAStartup)
{
#ifdef _WIN64
    WSADATA wsaData;
    [[maybe_unused]] int iResult;
    // Initialize Winsock
    if (_initWSAStartup) {
        if (!WSAStartupInitialized) {
            iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult) return false;
            WSAStartupInitialized = true;
        }
    }
#endif
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (serv_addr_string.size() > 0) {
#ifndef _WIN64
        if (inet_pton(AF_INET, serv_addr_string.c_str(), &serv_addr.sin_addr) <= 0) {
            std::string errorLine = "Ctcp::Common::init() ERROR : badd address string: " + serv_addr_string + "\n";
            printf("%s\n", errorLine.c_str());
            return false;
        }
#else
        if (InetPtonA(AF_INET, serv_addr_string.c_str(), &serv_addr.sin_addr) <= 0) {
            std::string errorLine = "Ctcp::Common::init() ERROR : badd address string: " + serv_addr_string + "\n";
            printf("%s", errorLine.c_str());
            return false;
        }
#endif
    }

    FD_ZERO(&read_fd_set);
    timeoutZero.tv_sec = 0;
    timeoutZero.tv_usec = 0;

    return true;
}

bool Ctcp::Common::deinit(void)
{
    close();
#ifdef _WIN64
    if (WSAStartupInitialized) {
        WSACleanup();
        WSAStartupInitialized = false;
    }
#endif
    return true;
}

int Ctcp::Common::recv(char* buf, int bufSize)
{
    return ::recv(hsocket, (char*)buf, bufSize, 0);
}

int Ctcp::Common::send(const char* buf, int bufSize)
{
    int numSent = 0;
    try {
        numSent = ::send(hsocket, (char*)buf, bufSize, MSG_NOSIGNAL);
    } catch(...) {
        // broken pipe error, destination may have closed, shutdown
        numSent = -1;
    }
    return numSent;
}

bool Ctcp::Common::isDataAvailable(void)
{
    /* Initialize the set of active sockets. */
    FD_ZERO(&read_fd_set);
    FD_SET(hsocket, &read_fd_set);
    timeoutZero.tv_sec = 0;
    timeoutZero.tv_usec = 0;

    int res = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeoutZero);
    if (res > 0) return true;
    if (res < 0) {
        return false;
    }

    return false;
}

bool Ctcp::Common::close(void)
{

    if (hsocket == INVALID_SOCKET) return false;

    shutdown(hsocket, SD_BOTH);
#ifdef _WIN64
    if (::closesocket(hsocket) != 0) return false;
#else
    if (::close(hsocket) != 0) return false;
#endif

    hsocket = INVALID_SOCKET;

    return true;
}

std::string Ctcp::Common::getIpAddressStringFromAddress(struct sockaddr* paddr)
{
    std::string _ipAddressString;
    char* pipAddressString = 0;
    if (paddr->sa_family == AF_INET) {
        in_addr& inAddr = ((struct sockaddr_in*)paddr)->sin_addr;
        int port = ((struct sockaddr_in*)paddr)->sin_port;
        pipAddressString = inet_ntoa(inAddr);
        if (pipAddressString) _ipAddressString = pipAddressString;
        _ipAddressString += ":" + to_string(ntohs(port));
    }
    return _ipAddressString;
}

std::string Ctcp::Common::getIpAddressString(void)
{
    return getIpAddressStringFromAddress((struct sockaddr*)&serv_addr);
}

SOCKET Ctcp::Common::getSocket(void)
{
    return hsocket;
}

void Ctcp::Common::reportError(std::string string1, std::string string2)
{
    #ifdef _WIN64
        std::string errorString;
        DWORD errorMessageID = ::GetLastError();
        if (errorMessageID != 0) {
            CHAR* messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

            errorString = "Error code: " + std::to_string(errorMessageID) + ", " + messageBuffer;

            //Free the buffer.
            LocalFree(messageBuffer);
        }
        printf("%s, %s, %s\n", string1.c_str(), string2.c_str(), errorString.c_str());
    #else
        printf("%s, %s, errno:%i\n", string1.c_str(), string2.c_str(), errno);
    #endif
}

// --------------------------------------------

Ctcp::Server::Server() :
    Common{},
    hlistenSocket{INVALID_SOCKET},
    peer_sockAddr{ 0 }
{
}

Ctcp::Server::Server(const Ctcp::Server& _other) :
    Common{ _other },
    hlistenSocket{ _other.hlistenSocket },
    peer_sockAddr{ _other.peer_sockAddr }
{
}

bool Ctcp::Server::init(string addrString, int _port, bool initWSAStartup)
{
    port = _port;
    serv_addr_string = addrString;
    Common::init(initWSAStartup);
    return true;
}

bool Ctcp::Server::listen(void)
{
    if (hlistenSocket != INVALID_SOCKET) {
    #ifdef _WIN64
            if (::closesocket(hlistenSocket) != 0) return false;
    #else
            if (::close(hlistenSocket) != 0) return false;
    #endif
    }

    hlistenSocket = ::socket(AF_INET, SOCK_STREAM, 0);

    if (hlistenSocket == INVALID_SOCKET) {
        reportError("Ctcp::Server::listen()", "ERROR : socket failed");
        return false;
    }

    serv_addr.sin_port = htons(port);

    #ifndef _WIN64
    int reuse = 1;
    if (setsockopt(hlistenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse))) {
        reportError("Ctcp::Server::listen()", "ERROR : SO_REUSEADDR failed");
        return false;
    }

    if (setsockopt(hlistenSocket, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse))) {
        reportError("Ctcp::Server::listen()", "ERROR : SO_REUSEADDR failed");
        return false;
    }
    #endif

    int stat = bind(hlistenSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if (stat == SOCKET_ERROR) {
        reportError("Ctcp::Server::listen()", "ERROR : bind failed");
        return false;
    }

    stat = ::listen(hlistenSocket, MAXLISTEN);

    if (stat == SOCKET_ERROR) {
        reportError("Ctcp::Server::listen()", "ERROR : listen failed");
        return false;
    }

    printf("Ctcp::Server::listen() created listen socket on %s - fd:%d\n", getIpAddressString().c_str(), (int)hlistenSocket);

    return true;
}

bool Ctcp::Server::accept(bool blocking)
{
    if (hlistenSocket == INVALID_SOCKET) return false;

    // Accept a client socket
#ifndef _WIN64
    socklen_t addrLen = sizeof(peer_sockAddr);
#else
    int addrLen = sizeof(peer_sockAddr);
#endif
    if (!blocking) {
#ifndef _WIN64
        hsocket = ::accept4(hlistenSocket, &peer_sockAddr, &addrLen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        printf("Ctcp::Server::accept() ERROR : blocking mode not supported\n");
        return false;
#endif
    } else {
        hsocket = ::accept(hlistenSocket, &peer_sockAddr, &addrLen);
    }

    if (hsocket == INVALID_SOCKET) {
        reportError("Ctcp::Server::accept()", "accept failed or socket closed");
        return false;
    }

    string line = "Ctcp::Server::accept() accepted a connection from ";
    line += getPeerSocket();
    printf("%s, fd:%d\n",line.c_str(), (int)hsocket);

    return true;
}

string Ctcp::Server::getPeerSocket(void)
{
    return getIpAddressStringFromAddress((struct sockaddr*)&peer_sockAddr);
}

/// Use this object only to hold the listen socket
/// most code uses same object to keep both listen and connection socket handle, for convenience.
/// Some code keeps these is in seperate objects. In this case make set the internal socket
/// to the same as the listen socket.
void Ctcp::Server::setAsOnlyAListenSocket(void)
{
    hsocket = hlistenSocket;
}

// --------------------------------------------

Ctcp::Client::Client() :
    Common{}
{
}

bool Ctcp::Client::connect(string addrString, int port)
{
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if ((hsocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        reportError("Ctcp::Client::connect()", "ERROR, Could not create socket");
        return false;
    }

#ifndef _WIN64
    if (inet_pton(AF_INET, addrString.c_str(), &serv_addr.sin_addr) <= 0) {
        reportError("Ctcp::Client::connect()", "ERROR, inet_pton error occured");
        return false;
    }
#else
    if (InetPtonA(AF_INET, addrString.c_str(), &serv_addr.sin_addr) <= 0) {
        reportError("Ctcp::Client::connect()", "ERROR, inet_pton error occured");
        close();
        return false;
    }
#endif

    if (::connect(hsocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        reportError("Ctcp::Client::connect()", "ERROR, Connect Failed to "+ addrString + ":" + std::to_string(port) );
        close();
        return false;
    }
    return true;
}

// -----------------------------------------------

CtcpString::CommonString::CommonString(Ctcp::Common* _pc)
    :
    pc{ _pc }
{
};

bool CtcpString::CommonString::recvString(string& recvString)
{
    int stringSize = 0;

    int stat = pc->recv((char*)&stringSize, (int)sizeof(stringSize));
#ifndef _WIN64
    if (stat == 0) {
        printf("CtcpString::CommonString::recvString() socket shutdown\n");
        return false;
    }
#else
    if ((stat == SOCKET_ERROR)||(!stat)) {
        int error = WSAGetLastError();
        if ((!error)||(error == WSAESHUTDOWN)||(error == WSAECONNRESET)) {
            printf("Ctcp::CommonString::recvString() ERROR, socket shutdown\n");
            return false;
        }
        printf("Ctcp::CommonString::recvString() ERROR, recvString failed, error code %d\n", error);
        return false;
    }
#endif
    if (stat != (int)sizeof(stringSize)) {
        printf("CtcpString::CommonString::recvString ERROR : recvString failed, could not get string size\n");
        return false;
    }
    recvString.resize(stringSize);
    char* pdata = (char*)recvString.data();
    int neededBytes = stringSize;
    while (neededBytes>0) {
        stat = pc->recv(pdata, neededBytes);
#ifndef _WIN64
        if (stat == 0) {
            printf("CtcpString::CommonString::recvString() socket shutdown\n");
            return false;
        }
#else
        if ((stat == SOCKET_ERROR) || (!stat)) {
            int error = WSAGetLastError();
            if ((!error) || (error == WSAESHUTDOWN) || (error == WSAECONNRESET)) {
                printf("CtcpString::CommonString::recvString() socket shutdown\n");
                return false;
            }
            printf("CtcpString::CommonString::recvString ERROR : recvString failed, error code: %d\n", error);
            return false;
        }
#endif
        if (stat < 0) {
            return false;
        }
        neededBytes -= stat;
        pdata += stat;
    }
    return true;
}

bool CtcpString::CommonString::sendString(string sendString)
{
    bool stat = true;
    int stringSize = (int)sendString.size();
    if (pc->send((char*)&stringSize, (int)sizeof(stringSize)) != (int)sizeof(stringSize)) {
        printf("CtcpString::CommonString::sendString ERROR : sendString failed \n");
        return false;
    }
    if (pc->send(sendString.data(), stringSize) != stringSize) {
        printf("CtcpString::CommonString::sendString ERROR : sendString failed \n");
        return false;
    }
    return stat;
}

CtcpString::Server::Server() :
    CommonString{ this }
{
};

CtcpString::Client::Client() :
    CommonString{ this }
{
};

CtcpString::CtcpString()
{
};
