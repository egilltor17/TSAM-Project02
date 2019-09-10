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
#include <regex>

#define BACKLOG  5

// Debug macro that prints "[file_name](function::line): " before the supled message
#define PRINT_ERROR(message) {\
    std::string _file = __FILE__; \
    printf("[%s](%s::%d): %s\n", _file.substr(_file.rfind('/') + 1, _file.npos).c_str(), __FUNCTION__, __LINE__, message); \
}

using namespace std;

int dgramSock; 
int rawSock;

// A signal handle that safely disconnects the client before terminating
void signalHandler(const int signum) {
    printf(" Signal (%d) received, closing connection.\n", signum);
    if(rawSock) { close(rawSock); }
    if(rawSock) { close(rawSock); }
    exit(signum);  
}

int main(int argc, char const *argv[]) {
    dgramSock = 0; 
    rawSock = 0; 
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);
    char buffer[1024] = {0}; 
    struct sockaddr_in serv_addr;
    std::string address = "";
    // struct sockaddr_in clie_addr;

    // register signal SIGINT and signal handler  
    signal(SIGINT, signalHandler); 

    //create a socket
    if((dgramSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        std::cout << "\n error dgram socket creation unsuccessful" << endl; 
        return -1; 
    } 
    if((rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { 
        std::cout << "\n error raw socket creation unsuccessful" << endl; 
        return -1; 
    } 


    // Require three arguments <host>, <ip port low> and <ip port high>
    if(argc != 4) {
        printf("Usage: client <host> <ip port low> <ip port high>\n");
        return -1;
    }

    address = argv[1];

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

    // initialize port in serv_addr object
    serv_addr.sin_family = AF_INET; 

    // Parse host name to IP address if possible
    // hostent *record = gethostbyname(argv[1]);
    // address = record ? inet_ntoa(*(in_addr *)record->h_addr) : argv[1];

    // // Convert address to binary 
    // if(inet_pton(AF_INET, address.c_str(), &serv_addr.sin_addr) <= 0) {   
    //     std::cout << "\nAddress was not accepted" << endl; 
    //     return -1; 
    // } 
    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)  
    { 
        string address = argv[1];
        if(address == "skel.ru.is"){
            inet_pton(AF_INET, "130.208.243.61", &serv_addr.sin_addr);
        } else {
            cout << "\nAddress was not accepted" << endl; 
            return -1; 
        }
    } 
    socklen_t addr_len = sizeof(serv_addr);
    std::cout << "Open ports: " << endl;
    int myport = 0, myiphdr = 0, myudphdr = 0, evilport = 0, checksumport = 0, checksum = 0, fakeport = 0, oracleport = 0;
    for(int i = lowPort; i <= highPort; i++) {
        serv_addr.sin_port = htons(i); 

    string message = "Scanning for victims";    
    struct udpwdesc{
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
        char description[21] = {0};
    };
    udpwdesc udphd;
    memcpy(udphd.description, message.c_str(), message.size() - 1);
    udphd.source = htons(45117);
    udphd.dest = htons(i);
    udphd.len = htons(8);		/* udp length */
    udphd.check = htons(0x403c - i);		/* udp checksum */
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250;
    memset(buffer, 0, sizeof (buffer));
    sendto(rawSock , &udphd, sizeof(udphd) + 20, 0, (struct sockaddr *)&serv_addr,(socklen_t)sizeof(serv_addr));    

        //set timeout of recvfrom
        setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        // cout << htons(serv_addr.sin_port) << endl;        
        if(recvfrom(rawSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &addr_len) >= 0) {
            string message = buffer + 28;    // Raw socket
            // message = buffer;
            cout << i << endl;
            cout << message << endl;
            std::cmatch cm;
            // Port
            if(std::regex_match(message.c_str(), cm, std::regex("^This is the port:(\\d+)"))) {
                std::cout << "Port: " << cm[1] << endl;
                fakeport = atoi(cm[1].str().c_str());
                for(int i = 0; i < 20; i++) {
                    printf("%02x ", (unsigned char)buffer[i]);
                }
                myport = htons(*(unsigned short*)(buffer + 22));
                
                cout <<  endl << myport << endl;
            }
            // Evil
            if(std::regex_match(message.c_str(), std::regex("^I only.*"))) {
                std::cout << "Evil" << endl;
                evilport = i;
            }
            // Checksum
            if(std::regex_match(message.c_str(), cm, std::regex("Please send.*of (\\d+)"))) {
                std::cout << "Checksum" << endl;
                checksumport = i;
                checksum = atoi(cm[1].str().c_str());
            }
            // Oracle
            if(std::regex_match(message.c_str(), std::regex("^I am the oracle.*\\n"))) {
                std::cout << "Oracle" << endl;
                oracleport = i;
            }
        } 
    }  
    return 0; 
} 