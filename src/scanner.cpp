//
// Port scanner for TSAM-409 Project 2
//
// Compile: g++ -Wall -std=c++11 scanner.cpp -o scanner
//          or run make
//
// Command line: ./scanner <ip host> <ip port low> <ip port high>
//
// Authors: Egill Torfason (egilltor17@ru.is)
//          Hallgrímur Andrésson (hallgrimura17@ru.is)
//
#include <stdio.h> 
#include <csignal>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <iostream>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netdb.h>

#define BACKLOG  5

// Debug macro that prints "[file_name](function::line): " before the supled message
#define PRINT_ERROR(message) {\
    std::string _file = __FILE__; \
    printf("[%s](%s::%d): %s\n", _file.substr(_file.rfind('/') + 1, _file.npos).c_str(), __FUNCTION__, __LINE__, message); \
}

using namespace std;

int servSock; 
int clieSock;

// A signal handle that safely disconnects the client before terminating
void signalHandler(const int signum) {
    printf(" Signal (%d) received, closing connection.\n", signum);
    if(servSock) { close(servSock); }
    if(clieSock) { close(clieSock); }
    exit(signum);  
}

int main(int argc, char const *argv[]) {
    servSock = 0; 
    clieSock = 0; 
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);
    char buffer[1024] = {0}; 
    struct sockaddr_in serv_addr;
    // struct sockaddr_in clie_addr;

    //create a socket
    if ((servSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    // if((servSock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { 
        std::cout << "\n error raw socket creation unsuccessful" << endl; 
        return -1; 
    } 
    // if((clieSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
    //     std::cout << "\n error socket creation unsuccessful" << endl; 
    //     return -1; 
    // } 

    // register signal SIGINT and signal handler  
    signal(SIGINT, signalHandler); 

    // Require three arguments <host>, <ip port low> and <ip port high>
    if(argc != 4) {
        printf("Usage: client <host> <ip port low> <ip port high>\n");
        return -1;
    }

    // <ip port low> <ip port high> must be integers
    if(!((lowPort = atoi(argv[2])) || argv[2][0] == 0) || !(highPort = atoi(argv[3]))) {
        printf("ip port high and low must be integers");
        return -1;
    }
    // <ip port low> must be lower or equal to <ip port high>
    if(lowPort > highPort) {
        printf("<ip port low> must be lower or equal to <ip port high>");
        return -1;
    }

    // <ip port low> and <ip port high> must be in range of valid ports
    if(lowPort <= 0 || lowPort > 65535) {
        printf("<ip port low> must be in range [0 - 65534]\n");
        return -1;
    }

    if(highPort <= 0 || highPort > 65535) {
        printf("<ip port high> must be in range [0 - 65534]\n");
        return -1;
    }

    //initialize port in serv_addr object
    serv_addr.sin_family = AF_INET; 
    // clie_addr.sin_family = AF_INET;
    // inet_pton(AF_INET, "127.0.0.1", &clie_addr.sin_addr);
    // clie_addr.sin_port = htons(34810);
    // if(bind(clieSock, (struct sockaddr*)&clie_addr, sizeof(clie_addr)) < 0) {
    //     std::cout << "bind error" << endl;
    //     return -1;
    // }
    // std::cout << htons(clie_addr.sin_port) << endl;
    
    std::string address = argv[1];
    // Parse host name to IP address if possible
    hostent *record = gethostbyname(argv[1]);
    address = record ? inet_ntoa(*(in_addr *)record->h_addr) : argv[1];
    
    //  convert address to binary 
    if(inet_pton(AF_INET, address.c_str(), &serv_addr.sin_addr) <= 0) {   
        std::cout << "\nAddress was not accepted" << endl; 
        return -1; 
    } 
    std::cout << "Open ports: " << endl;
    for(int i = lowPort; i <= highPort; i++) {
        serv_addr.sin_port = htons(i); 
        socklen_t addr_len = sizeof(serv_addr);
        // iphdr ip;
        // ip.tos = ;
        // ip.tot_len;
        // ip.id;
        // ip.frag_off;
        // ip.ttl;
        // ip.protocol;
        // ip.check;
        // ip.saddr;
        // ip.daddr;
        // if (getsockname(rawSock, (struct sockaddr *)&serv_addr, &addr_len) == -1)
        //     perror("getsockname");
        // else
        //     printf("port number %d\n", serv_addr.sin_port);

        // connect to address and port
        // std::cout << i << " ";
        // fflush(stdout);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 250;
        memset (buffer, 0, sizeof (buffer));
        sendto(servSock , "Scanning for ivctims" , 21, 0, (struct sockaddr *)&serv_addr,(socklen_t)sizeof(serv_addr));
        //set timeout of recvfrom
        setsockopt(servSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        // cout << htons(serv_addr.sin_port) << endl;        
        if(recvfrom(servSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &addr_len) >= 0 ){
            string message = buffer;
            cout << i << endl;
            cout << message << endl;
        }
        else {
            // cout << read << endl;
        }
    }
        string message = "Scanning for victims";        
        struct udpwdesc {
            uint16_t source;
            uint16_t dest;
            uint16_t len;
            uint16_t check;
            char description[21] = {0};
        };
        udpwdesc udphd;
        //works with port 64702 and check const 0xEDB8
        udphd.source = 0;
        udphd.dest = htons(i);
        udphd.len = htons((int)sizeof(udphd));		/* udp length */
        udphd.check = htons(0x403c - i);		/* udp checksum */
        memcpy(udphd.description, message.c_str(), message.size() - 1);
    return 0; 
} 