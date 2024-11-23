#pragma once
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
#include <stdint.h>
#include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
//#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#endif


#define CTCP_DEFAULT_PORT
#include <string>

#ifndef _WIN64
typedef int SOCKET;
const int INVALID_SOCKET = -1;
const int SOCKET_ERROR = -1;
const int SD_BOTH = SHUT_RDWR;
typedef unsigned int DWORD;
#endif

class Ctcp {
public:
    class Common {
    protected:
        struct sockaddr_in serv_addr;
        int port;
        std::string serv_addr_string;
        SOCKET hsocket;
        fd_set read_fd_set;
        struct timeval timeoutZero;
        static bool WSAStartupInitialized;    // on Windows system, determine whether this class is to initialize or not

    public:
        Common();
        Common(const Ctcp::Common& _other);
        ~Common();
        bool init(bool _initWSAStartup = true);
        bool deinit(void);
        int recv(char* buf, int bufSize);
        int send(const char* buf, int bufSize);
        bool isDataAvailable(void);
        std::string getIpAddressString(void);
        std::string getIpAddressStringFromAddress(struct sockaddr*);
        SOCKET getSocket(void);
        bool close(void);
        void reportError(std::string string1, std::string string2);
        bool socketValid(void) { return (((int)hsocket) >= 0);  }
    };

 public:
     class Server : public Common {
         const int MAXLISTEN = 10;
         SOCKET hlistenSocket = 0;
         struct sockaddr peer_sockAddr;
     public:
         Server();
         Server(const Server& other);
         bool init(std::string addrString, int port, bool initWSAStartup = false);
         bool listen(void);
         bool accept(bool blocking = true);
         void setAsOnlyAListenSocket(void);
         std::string getPeerSocket(void);
         int getPeerSocketIpAddr(void) { 
             struct sockaddr_in* p = (struct sockaddr_in*)&peer_sockAddr;
             return  ntohl(p->sin_addr.s_addr); 
         }
     } server;

    class Client : public Common {
    public:
        Client();
        bool connect(std::string addrString, int port);
    } client;

public:
    Ctcp();
};


class CtcpString {
    class CommonString {
        Ctcp::Common* pc;
    public:
        CommonString(Ctcp::Common* _pc);
        bool recvString(std::string& recvString);
        bool sendString(const std::string recvString);
    };
public:
    class Server : public Ctcp::Server, public CommonString {
    public:
        Server();
    } server;

    class Client : public Ctcp::Client, public CommonString {
    public:
        Client();
    } client;
    CtcpString();
};
