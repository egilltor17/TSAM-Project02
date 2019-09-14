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
#define BUFFER_SIZE 1024

// Debug macro that prints "[file_name](function::line): " before the supled message
#define PRINT_ERROR(message) {\
    std::string _file = __FILE__; \
    printf("[%s](%s::%d): %s\n", _file.substr(_file.rfind('/') + 1, _file.npos).c_str(), __FUNCTION__, __LINE__, message); \
}

using namespace std;

int dgramSock;
int rawSock;
int rawIpSock; 


struct udpwdesc {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
    uint16_t offset;
};
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// A signal handle that safely disconnects the client before terminating
void signalHandler(const int signum) {
    printf(" Signal (%d) received, closing connection.\n", signum);
    if(dgramSock) { close(dgramSock); }
    if(rawIpSock) { close(rawIpSock); }
    if(rawSock) { close(rawSock); }

    exit(signum);
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main(int argc, char const *argv[]) {
    dgramSock = 0;
    rawSock = 0;
    rawIpSock = 0; 

    int val = 1;
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);
    char buffer[BUFFER_SIZE] = {0};
    char evilBuffer[BUFFER_SIZE] = {0};
    struct sockaddr_in serv_addr;
    std::string address = "";
    std::string message = "";
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
    if((rawIpSock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { 
        std::cout << "\n error rawIp socket creation unsuccessful" << endl; 
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
    u_int16_t myPort = 45117;
    socklen_t addr_len = sizeof(serv_addr);
    pseudo_header psh;
    psh.source_address = inet_addr("127.0.0.1");
    psh.dest_address = serv_addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(10);
    udpwdesc udphd;
    udphd.source = htons(myPort);
    udphd.dest = 0;
    udphd.len = htons(10);
    udphd.check = 0;
    udphd.offset = 0;
    
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    for(int i = lowPort; i <= highPort; i++) {
        serv_addr.sin_port = htons(i);
        sendto(dgramSock , "scanning for victims", 21, 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
    }
    setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(rawIpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(rawIpSock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

        
    u_int32_t myAddress;
    bool firstRecv = true;
    string easyPort = "";
    int oraclePort = 0;
    string evilPort = "";
    string secretQuote;
    memset(buffer, 0, sizeof (buffer));
    while(recvfrom(rawSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &addr_len) >= 0)
    {
        // cout << "receiving" << endl;
        // cout << htons(serv_addr.sin_port) << endl;            
        if(firstRecv){
            firstRecv = false;
            myAddress = (buffer[19] << 24) + (buffer[18] << 16) + (buffer[17] << 8) + buffer[16];
            psh.source_address = myAddress;
            // printf("myaddress %02x\n", myAddress);
        }
        
        string message = buffer + 28;    // Raw socket
        

        // message = buffer;
        unsigned short somePort = ((unsigned char)(buffer[20]) << 8) + (unsigned char)(buffer[21]);
        // printf("some port %d\n", somePort);
        // cout << "message " <<  message << endl;
        std::cmatch cm;

        // Checksum
        if(std::regex_match(message.c_str(), cm, std::regex(".*checksum.* of (\\d+)"))) {
            // std::cout << "Checksum " << cm[1] << endl;
            udphd.dest = htons(somePort);  
            udphd.check = 0;            
            memcpy(buffer, (char*)&psh, sizeof(psh));
            memcpy(buffer + sizeof(psh), (char*)&udphd, sizeof(udphd));
            udphd.check = csum((unsigned short*)&buffer, sizeof(psh) + sizeof(udphd));
            memset(buffer, 0, sizeof (buffer));

            unsigned short checksum = atoi(cm[1].str().c_str());
            udphd.offset = -(htons((unsigned short)(checksum)) - udphd.check);
            // printf("desired %x current %x, offset %x\n", (unsigned short)(~checksum), udphd.check, (unsigned short)udphd.offset);
            udphd.check = 0;
            memcpy(buffer, (char*)&psh, sizeof(psh));
            memcpy(buffer + sizeof(psh), (char*)&udphd, sizeof(udphd));
            udphd.check = csum((unsigned short*)&buffer, sizeof(psh) + sizeof(udphd));
            memset(buffer, 0, sizeof (buffer));
            sendto(rawSock , &udphd, sizeof(udphd), 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));

        }
        // Port
        else if(std::regex_match(message.c_str(), cm, std::regex("^This is the port:(\\d+)"))) {
            // std::cout << "Port: " << cm[1] << endl;
            easyPort = cm[1].str();

        }
        // Evil
        else if(std::regex_match(message.c_str(), std::regex("^I only.*"))) {
            // cout << "Evil" << endl;
            udphd.dest = htons(somePort);
            memcpy(evilBuffer, buffer, sizeof(buffer));
            // Swap source and destination address
            memcpy(evilBuffer+16, buffer+12, 4UL);
            memcpy(evilBuffer+12, buffer+16, 4UL);
            // Add our UDP header
            memcpy(evilBuffer+20, &udphd, sizeof(udphd));
            // With a sprinkle of evil
            evilBuffer[6] |= 0x80;
            sendto(rawIpSock , &evilBuffer, 112, 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
        }
        // Oracle
        else if(std::regex_match(message.c_str(), std::regex("^I am the oracle.*\\n"))) {
            // std::cout << "Oracle" << endl;
            oraclePort = somePort;
        }
        else if(std::regex_match(message.c_str(), cm, std::regex("Good.*\\n\"(.*)\""))) {
            // std::cout << message << endl;
            secretQuote = cm[1].str();
            // cout << secretQuote << endl;
        }
        else if(std::regex_match(message.c_str(), cm, std::regex("Hello.*\\n(\\d+)"))) {
            evilPort = cm[1].str();
        }

        memset(buffer, 0, sizeof(buffer));
    }  
    serv_addr.sin_port = htons(oraclePort);
    cout << "evil port " << evilPort << "\nsecret message " << secretQuote << endl;
    string phrase = easyPort + (string)", " + evilPort;
    sendto(dgramSock , phrase.c_str(), phrase.size(), 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
    u_int16_t port = 0;
    while(recvfrom(rawSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &addr_len) > 0) {
        message = buffer+28;
        // message = buffer;
        cout << "Reading port sequence: " << message << endl;
        std::regex re("(\\d{3}\\d+)");
        std::sregex_iterator next(message.begin(), message.end(), re);
        std::sregex_iterator end;
        while(next != end) {
            if(port) {
                serv_addr.sin_port = htons(port);
                sendto(dgramSock , "knock\n", 6UL, 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
            }
            std::smatch match = *next;
            port = atoi(match.str().c_str());
            std::cout << port << "\n";
            next++;
        } 
        if(port) {
            serv_addr.sin_port = htons(port);
            // sendto(dgramSock , secretQuote.c_str(), secretQuote.size(), 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
            sendto(dgramSock , "How much wood could a woodchuck chuck if a woodchuck could chuck wood!\n", 72, 0, (struct sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
            port = 0;
        }
        memset(buffer, 0, sizeof(buffer));
    }
    return 0; 
} 
