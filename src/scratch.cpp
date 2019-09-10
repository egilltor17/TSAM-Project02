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

/* 
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>
#include <iostream>

int resolvehelper(const char *hostname, int family, const char *service, sockaddr_storage *pAddr) {
    int result;
    addrinfo *result_list = NULL;
    addrinfo hints = {};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM; // without this flag, getaddrinfo will return 3x the number of addresses (one for each socket type).
    result = getaddrinfo(hostname, service, &hints, &result_list);
    if(result == 0) {
        //ASSERT(result_list->ai_addrlen <= sizeof(sockaddr_in));
        memcpy(pAddr, result_list->ai_addr, result_list->ai_addrlen);
        freeaddrinfo(result_list);
    }
    return result;
}

int main() {
    int result = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    char szIP[100];

    sockaddr_in addrListen = {}; // zero-int, sin_port is 0, which picks a random port for bind.
    addrListen.sin_family = AF_INET;
    result = bind(sock, (sockaddr *)&addrListen, sizeof(addrListen));
    if(result == -1) {
        int lasterror = errno;
        std::cout << "error: " << lasterror;
        exit(1);
    }

    sockaddr_storage addrDest = {};
    result = resolvehelper("192.168.0.4", AF_INET, "9000", &addrDest);
    if(result != 0) {
        int lasterror = errno;
        std::cout << "error: " << lasterror;
        exit(1);
    }

    const char *msg = "Jane Doe";
    size_t msg_length = strlen(msg);

    result = sendto(sock, msg, msg_length, 0, (sockaddr *)&addrDest, sizeof(addrDest));

    std::cout << result << " bytes sent" << std::endl;

    return 0;
} 
*/


unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes-=2;
	}
	if(nbytes == 1) {
		oddbyte=0;
		*((u_char*) & oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16)+(sum & 0xffff);
	sum = sum + (sum >> 16);
	answer=(short)~sum;
	
	return(answer);
}


uint16_t csum(void *buf, int cb) {
    uint16_t *ptr = (uint16_t *)buf;
    //initialize the sum with the last byte in case of odd size, otherwise to zero
    int32_t sum = (cb&1) ? ((uint8_t)buf)[cb-1] : 0;
    cb/=2;
    while(cb--) sum += *ptr++;
    return (uint16_t)~((sum>>16)+(sum & 0xffff));
}