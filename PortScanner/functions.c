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
#include "struc.h"
//int flag1=0,synflag=0, finFlag=0, ackFlag=0, nullFlag=0, xmasFlag=0,tcpFlag=0,udpFlag=0;



unsigned short checksum(unsigned short *addr,int length)
{
        register int add = 0;
        u_short ans = 0;
        register u_short *w = addr;
        register int nleft = length;

        while (nleft > 1)
        {
                add += *w++;
                nleft -= 2;
        }

        if (nleft == 1)
        {
                *(u_char *)(&ans) = *(u_char *)w ;
                add += ans;
        }

        add = (add >> 16) + (add &0xffff);
        add += (add >> 16);
        ans = ~add;
        return(ans);
}

int respondtimeout(int filedes, char *buf, int len, int timeout) // reference - beej
{
    fd_set fds;
    int n;
    struct timeval tv; 
// set up the file descriptor set
FD_ZERO(&fds);
FD_SET(filedes, &fds);
// set up the struct timeval for the timeout
tv.tv_sec = timeout;
tv.tv_usec = 0;
// wait until timeout or data received
n = select(filedes+1, &fds, NULL, NULL, &tv);
if (n == 0) return -2; // timeout!
if (n == -1) return -1; // error
// data must be here, so do a normal recv()
return recv(filedes, buf, len, 0);
}
void service(char *IP,int port_no)
{
        char port[10];
 int flag1=0;
       snprintf(port, 10,"%d",port_no);
                
        struct addrinfo hints, *res;
        char *p,buf[256],serviceName[20],*temp="a",msg[512] = "GET ";
        char *service[10] = {"SSH","HTTP","SMTP","POP","IMAP","WHOIS","FTP"};
        struct servent *appl_name;        
        int test, byte_count, iArgs,iIndex=0,i,k,stream_socket,dgram_socket,flag=0,connectID,n,arrIPsIndex=0;        
        fd_set fds;         
        int state;
            struct timeval tv; 
        int errValue;        
        char *strServ;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version                                                                        
                                                
        if(flag1==1)        // for tcp or no protocol specified        
        {
        
                hints.ai_socktype = SOCK_STREAM;
                if ((test = getaddrinfo(IP,port,&hints, &res)) != 0) 
                { 
}                
                stream_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);        //create socket compatible with tcp ports
                        
                tv.tv_sec = 10;                // 10 second timeout
                tv.tv_usec = 0;
                state = setsockopt(stream_socket,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
                state = setsockopt(stream_socket,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

                connectID = connect(stream_socket, res->ai_addr, res->ai_addrlen);        //establish connection

                if(connectID != -1)        // port is open
                {                                                        
if(strcmp(port,"43") == 0)//WHOIS
                        {
                                strcpy(msg,"WHOIS -h com.whois-servers.net ");
                                strcat(msg,IP);
                                send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
                                n = respondtimeout(stream_socket, buf, sizeof buf, 10);
                        }
                        if(strcmp(port,"80") == 0) //HTTP
                        {
                                strcat(msg,IP);
                                strcat(msg," HTTP/1.1\n\n");                                                                        
                                send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
                                n = respondtimeout(stream_socket, buf, sizeof buf, 10); // 10 second timeout
                                
                        }
                        if(strcmp(port,"143") == 0)        //IMAP
                        {
                                strcpy(msg,"fetch 1");
                                send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
                                n = respondtimeout(stream_socket, buf, sizeof buf, 10);
                        }
                        else        //other services
n = respondtimeout(stream_socket, buf, sizeof buf, 10);
                        }                                        

                        if (n == -1) 
                        {}
                        else if (n == -2) 
                        {} 
                        else 
                        { buf[n] = '\0';
                                if(strcmp(port,"80")==0)
                                {
                                        flag = 1;
                                        strServ = (char *)malloc(10);
                                        strxfrm(strServ,buf,9);
                                      //  printf("%s\t%s\tOpen\t%s\tTCP\n",stripNewline(IP,strlen(IP)),port,strServ);                                        
                                }
                                else if(strcmp(port,"22")==0)
                                {
                                        flag = 1;
                                        strServ = (char *)malloc(10);
                                        strServ = strstr(buf,"Open");
                                       // strServ = stripNewline(strServ,strlen(strServ));
                                       // printf("%s\t%s\tOpen\t%s\tTCP\n",stripNewline(IP,strlen(IP)),port,strServ);                                        
                                }
                                else
                                {
                                        for(k=0;k<7;k++)
                                        {
                                                  p = strstr(buf,service[k]);        // to get exact service name                                         
                                                  if(p)
                                                   {
                                                        flag = 1;
                                         //               printf("%s\t%s\tOpen\t%s\t\tTCP\n",stripNewline(IP,strlen(IP)),port,service[k]);                                                
                                                        break;
                                                   }
                                                   k++;
                                        }
                                }        
                                if(flag == 0)
                                {                                        
                                     //   printf("%s\t%s\tOpen\t%s\t\tTCP\n",stripNewline(IP,strlen(IP)),port,buf);}
}
}}
                                
  else
                {
// printf("%s\t%s\tClosed\t\t\tTCP\n",stripNewline(IP,strlen(IP)),port);                        
                }                
                        
       
}        
char *stripNewline(char *str, int size)	// remove new line character 	
{
    int i;   
    for (  i = 0; i < size; ++i )
    {
        if ( str[i] == '\n' )
        {
            str[i] = '\0';           
            return str;   
        }
    }  
    return str;    
}

