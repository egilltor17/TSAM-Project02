
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <iostream>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define BACKLOG  5
using namespace std;
int main(int argc, char const *argv[]) 
{
    int servSock; 
    int clieSock; 
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);
    char buffer[1024] = {0}; 
    struct sockaddr_in serv_addr;
    // struct sockaddr_in clie_addr;

    //create a socket
    // if ((servSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) 
    if ((servSock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) 
    { 
        cout << "\n error socket creation unsuccessful" << endl; 
        return -1; 
    } 
    if ((clieSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) 
    { 
        cout << "\n error socket creation unsuccessful" << endl; 
        return -1; 
    } 
    if(argc < 3)
    {
        cout << "\n Not enough arguements" << endl; 
        return -1; 
    }
    //initialize port in serv_addr object
    serv_addr.sin_family = AF_INET; 
    // clie_addr.sin_family = AF_INET;
    // inet_pton(AF_INET, "127.0.0.1", &clie_addr.sin_addr);
    // clie_addr.sin_port = htons(34810);
    // if(bind(clieSock, (struct sockaddr*)&clie_addr, sizeof(clie_addr)) < 0){
    //     cout << "bind error" << endl;
    //     return -1;
    // }
    // cout << htons(clie_addr.sin_port) << endl;
    //  convert address to binary 
    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)  
    { 
        string address = argv[1];
        if(address == "skel.ru.is"){
            inet_pton(AF_INET, "130.208.243.61", &serv_addr.sin_addr);
        }
        else{
            cout << "\nAddress was not accepted" << endl; 
            return -1; 
        }
    } 
    cout << "Open ports: " << endl;
    for(int i = lowPort; i <= highPort; i++){
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
        string message = "Scanning for victims";
        struct udpwdesc{
            uint16_t source;
            uint16_t dest;
            uint16_t len;
            uint16_t check;
            char description[21] = {0};
        };
        udpwdesc udphd;
        //works with port 64702 and check const 0xEDB8
        udphd.source = htons(45117);
        udphd.dest = htons(i);
        udphd.len = htons(8);		/* udp length */
        udphd.check = htons(0x403c - i);		/* udp checksum */
        
        memcpy(udphd.description, message.c_str(), message.size() - 1);
        // connect to address and port
        // cout << i << " ";
        // fflush(stdout);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 250;
        memset (buffer, 0, sizeof (buffer));
        sendto(servSock , &udphd , sizeof(udphd), 0, (struct sockaddr *)&serv_addr,(socklen_t)sizeof(serv_addr));
        //set timeout of recvfrom
        setsockopt(servSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        // cout << htons(serv_addr.sin_port) << endl;        
        if(recvfrom(servSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, &addr_len) >= 0 ){
            string message = buffer + 28;
            cout << i << endl;
            cout << message << endl;
        }
        else
        {
            // cout << read << endl;
        }
    }
    return 0; 
} 