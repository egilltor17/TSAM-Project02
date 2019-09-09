//
// Simple client for TSAM-409 Project 2 b
//
// Compile: g++ -Wall -std=c++11 scanner.cpp -o scanner
//
// Command line: ./client <ip host> <ip port low> <ip port high>
//
// Author: Egill Torfason (egilltor17@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <csignal>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#define BUFFER_SIZE 1024    // max request length

// Debug macro that prints "[file_name](function::line): " before the supled message
#define PRINT_ERROR(message) {\
    std::string _file = __FILE__; \
    printf("[%s](%s::%d): %s\n", _file.substr(_file.rfind('/') + 1, _file.npos).c_str(), __FUNCTION__, __LINE__, message); \
}
// Macro that is used to copy 0 to BUFFER_SIZE chars when takin user input
#define COPY_SIZE(buf) ((sizeof(buf) < BUFFER_SIZE ? sizeof(buf) : BUFFER_SIZE) - 1)

int sock = 0;

// A signal handle that safely disconnects the client before terminating
void signalHandler(const int signum) {
    printf(" Signal (%d) received, closing connection.\n", signum);
    if(sock) { close(sock); }
    exit(signum);  
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server; 
    std::string host;
    sock = 0;
    int ip_low = 0;
    int ip_high = 0;

    // register signal SIGINT and signal handler  
    signal(SIGINT, signalHandler); 

    // Require three arguments <host>, <ip port low> and <ip port high>
    if(argc != 4) {
        printf("Usage: client <host> <ip port low> <ip port high>\n");
        exit(0);
    }

    // <ip port low> <ip port high> must be integers
    if(!((ip_low = atoi(argv[2])) || argv[2][0] == 0) || !(ip_high = atoi(argv[3]))) {
        printf("ip port high and low must be integers");
        return -1;
    }
    // <ip port low> must be lower or equal to <ip port high>
    if(ip_low > ip_high) {
        printf("<ip port low> must be lower or equal to <ip port high>");
        return -1;
    }

    // <ip port low> and <ip port high> must be in range of valid ports
    if(ip_low <= 0 || ip_low > 65535) {
        printf("<ip port low> must be in range [0 - 65534]\n");
        return -1;
    }

    if(ip_high <= 0 || ip_high > 65535) {
        printf("<ip port high> must be in range [0 - 65534]\n");
        return -1;
    }

    // Parse host name to IP address if possible
    // http://www.cplusplus.com/forum/articles/9742/
    hostent *record = gethostbyname(argv[1]);
    host = record ? inet_ntoa(*(in_addr *)record->h_addr) : argv[1];

    // Set type of connection
    server.sin_family = AF_INET;

    // Scanning loop
    for(int i = ip_low; i <= ip_high; i++) {

        /* 
        // Open a socket TCP
        if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
            PRINT_ERROR("Socket creation error");
            return -1;
        }
        */
        
        // Open a socket UDP
        if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { 
            PRINT_ERROR("Socket creation error");
            return -1;
        }
        
        /*
        // Open a socket RAW (might need sudo)
        if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { 
            PRINT_ERROR("Socket creation error");
            return -1;
        }
        */

        // Set port
        server.sin_port = htons(i); 
 
        // Convert IPv4 and IPv6 addresses from text to binary form 
        if(inet_pton(AF_INET, host.c_str(), &server.sin_addr) <= 0) { 
            PRINT_ERROR("Invalid address/ Address not supported");
            return -1;
        } 
    
        // Connext to the socket
        if(connect(sock, (sockaddr *)&server, sizeof(server)) < 0) { 
            printf("Port: %d - Connection failed\n", i);
            // PRINT_ERROR("Connection Failed");
            // return -1;
        }
        
        if(sendto(sock, "msg", sizeof("msg"), 0, (sockaddr *)&server, sizeof(server)) < 0) {
            printf("someting happend :(\n");
        }

        close(sock);
    }
    return 0;
}