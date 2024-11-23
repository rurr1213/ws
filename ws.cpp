#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include "TcpStringClientServer.h"

TcpStringServer tcpStringserver;

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
        string text  = "hi this is ravi";
        TcpStringClient tcpStringClient("127.0.0.1", 0);
        tcpStringClient.doShell();
//        tcpStringClient.sendString(text, text.size());
    } else {
        tcpStringserver.runSever();
    }
}
