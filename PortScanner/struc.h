#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <math.h>
#include <sys/time.h>
#include <netinet/in.h>
#include<errno.h>
#include <netdb.h>
#include<netinet/ether.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<time.h>
#include<malloc.h>
#include<arpa/inet.h>



struct pseudohdr
{
        struct tcphdr tcp;
        struct in_addr srcIp;
        struct in_addr dstIp;
        unsigned char padd;
        unsigned char protoNo;
        unsigned short length;
};

struct portiphead 
{
        char *ipaddr;
        int start_port;
        int end_port;        
};
