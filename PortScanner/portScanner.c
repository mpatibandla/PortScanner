#include<stdio.h>
#include<stdlib.h>
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
//#include "functions.h"
//port scanning function

void portscanner(struct portiphead info);
//checksum function
unsigned short checksum(unsigned short *addr,int length);
//all the scans---who is, http etc and timeouts
int respondtimeout(int file, char *buffer, int l, int time);
//WHOIS etc services
void service(char *ip,int portno);

//tcp scan
//udp scan
//services
//testing
//
int tcpflag=0,udpflag=0,fileflag=0,ipflag=0,synflag=0,finflag=0,xmasflag=0,ackflag=0,nullflag=0,scanflag=0,ipno;


void main(int argc, char *argv[])
{
struct portiphead scan;
char ip[50],trans[5],fname[30];
char *p1,*p2;
FILE *file;
//char port1[30],port2[30];
char ipaddr[50];
int portnos[100];
char port1[20],port2[20];
//char portstart[30],portend[30];
int portstart,portend;
int start,pstart,pend,end,thread,opt,j,index;
int i,k,flag,flag2;
char *iparr[50][50];
if(argc<2)
{
printf("required input.. --help for options");
}
for(k=0;k<argc;k++)
{
if(strcmp("--help",argv[k])==0)
{
printf("\nOptions\n--help<display invocation options>\n--ports<ports to scan>\n--ip<ip address to scan>\n--prefix<ip prefix to scan>\n--file<file name containing ip addresses to scan>\n--speedup<parallel threads to use>\n--scan<one or more scans>\n");
return;
}
if(strcmp("--ports",argv[k])==0)
{
//port1=argv[k+1];
//port2=argv[k+2];
portstart=strcpy(port1,argv[k+1]);
pstart=atoi(port1);
portend=strcpy(port2,argv[k+2]);
pend=atoi(port2);
flag=1;
printf("%d %d",pstart,pend);
//flag2=1;
}
//ip
if(strcmp("--ip",argv[k])==0)
{
ipflag=1;
strcpy(ipaddr,argv[k+1]);
}
//file io
if(strcmp("--file",argv[k])==0)
{
fileflag=1;
strcpy(fname,argv[k+1]);
printf("file name %s",fname);
file=fopen(fname,"r");
if(file==NULL)
printf("file couldnot be opened or doesnt exist");
while(!feof(file))
{
fscanf(file,"%s",iparr[index]);
index++;
}
fclose(file);
}
if(strcmp("--speedup",argv[k])==0)
{
thread=atoi(argv[k+1]);
}
if(strcmp("--scan",argv[k])==0)
{
tcpflag=1;
for(i=k;i<argc;i++)
{
if(strcmp("SYN",argv[i+1])==0)
synflag=1;
if(strcmp("FIN",argv[i+1])==0)
finflag=1;
else if(strcmp("ACK",argv[i+1])==0)
ackflag=1;
else if(strcmp("NULL",argv[i+1])==0)
nullflag=1;
else if(strcmp("XMAS",argv[i+1])==0)
xmasflag=1;
else if(strcmp("UDP",argv[i+1])==0)
udpflag=1;
}
}

if(tcpflag==0)
{
synflag=1;
finflag=1;
       ackflag=1;
                        nullflag=1;
                        xmasflag=1;
            }

//if(scanflag==0)
if(flag==0)
{
pstart=1;
pend=1024;
}
for(j=pstart;j<=pend;j++)
{
portnos[i]=j;
j++;
}
if(fileflag==1)
{
printf("IP addresses:");
for(ipno=0;ipno<index;ipno++)
{
scan.ipaddr=iparr[ipno];
scan.start_port =pstart;
scan.end_port =pend;
printf("IP Address:%s\n ", iparr[ipno]);
portscanner(scan);
}}
else if(ipflag==1)
{
scan.ipaddr=ipaddr;
scan.start_port =pstart;
scan.end_port =pend;
printf("IP Address:%s\n ", ipaddr);
//portscanner(scan);
printf("ip:%s\n starting port:%d \n ending port:%d\n",scan.ipaddr,scan.start_port,scan.end_port);
portscanner(scan);
printf("function done");
}}
//printf("ip:%s\n starting port:%d \n ending port:%d\n",scan.ipaddr,scan.start_port,scan.end_port);


}

//file


//tcp-syn
//flags
//checksum
//timed



void portscanner (struct portiphead info)
{
        int port,nbytes;
        char hostname[1024],buf[4096];
        struct addrinfo hints, *servinfo, *p;
            char ipaddr[30];
        char finalip[20],fileName[20];
        int k,j,l,m;
        struct portiphead tpi;
        tpi=info;
                
        for (port=tpi.start_port; port<=tpi.end_port; port++)        
        {
               if(tcpflag==0)
               {
                goto label;}

                        char bbuf[10];
                        snprintf(bbuf, 10, "%d", port);
                        int h,z;        
                        h=gethostname(hostname,100);
                        struct hostent *hstent;
 /*                       struct in_addr **addr_list;
                        hstent=gethostbyname(hostname);
                        addr_list=(struct in_addr**)hstent->h_addr_list;
                        for(z=0;addr_list[z]!=NULL;z++)
                        {
                                strcpy(finalip,inet_ntoa(*addr_list[z]));
                                break;
                                label:;
                        }*/
                       label:  if(synflag==1)
                        {
                                int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
                        //        int s_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
                                char packet[4096];
                                struct ip *iphdr = (struct ip *) packet;
                                struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
                                struct sockaddr_in sin;
                                struct sockaddr_storage pin;

                                sin.sin_family = AF_INET;
                                sin.sin_port = htons (port);
                                sin.sin_addr.s_addr = inet_addr(tpi.ipaddr);

                                memset (packet, 0, 4096);
                                iphdr->ip_hl = 5;
                                iphdr->ip_v = 4;
                                iphdr->ip_tos = 0;
                                iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
                                iphdr->ip_id = htonl (54321);
                                iphdr->ip_off = 0;
                                iphdr->ip_ttl = 255;
                                iphdr->ip_p = 6;
                                iphdr->ip_sum = 0;
                                iphdr->ip_src.s_addr = inet_addr (finalip);
                                iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

                                tcphddr->source = htons (1234);
                                tcphddr->dest = htons (port);
                                tcphddr->seq = htonl(random ());
                                tcphddr->ack_seq = 0;
                                tcphddr->doff = 5;
                                tcphddr->syn = 1;
                                tcphddr->window = ntohs(65535);
                                tcphddr->check = 0;
                                tcphddr->urg_ptr = 0;

                                struct pseudohdr pseudoheader;
                                memset(&pseudoheader, 0, sizeof(struct pseudohdr));
                                pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
                                pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
                                pseudoheader.padd = 0;
                                pseudoheader.protoNo = IPPROTO_TCP;
                                pseudoheader.length = htons(sizeof(struct tcphdr));
                                memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

                                tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
                                iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

                                int t=1;
                                const int *val = &t;
                        
                                int t_icmp=1;
                                const int *val_icmp = &t_icmp;
                        
                                if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
// if (setsockopt (s_icmp, IPPROTO_IP, IP_HDRINCL, val_icmp, sizeof (t_icmp)) < 0){}
                                //printf ("HDRINCL for ICMP cannot be set.\n");
 int i;
                                if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
                                //printf("Error in sending packet\n");
//if (sendto(s_icmp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
                                //printf("Error in sending packet\n");
 else
                                printf("Packet sent successfully\n");

                                for (i=0;i<100;i++)
                                {
                                        struct timeval tv;
                                        tv.tv_sec = 2;
                                        tv.tv_usec = 100000;

                                        setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  //                                      setsockopt(s_icmp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
//                                        setsockopt(s_icmp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


                                        nbytes=0;
                                        memset(buf,0,4096);
int fromlen = sizeof (pin);
//fcntl(s_icmp, F_SETFL, O_NONBLOCK);
                
                                        nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);        
                                                
  //                                      icmpnbytes = recvfrom(s_icmp,buf_icmp,4096, 0,(struct sockaddr *)&pin,&fromlen);
                                                                        
                                        
      //                                  struct ip *iphdr_icmp = (struct ip *)(buf_icmp);
    //                                            struct icmp *icmphdr = (struct icmp *)(buf_icmp + sizeof(struct ip));
        /*                                
                                        if(iphdr_icmp->ip_p==1)
                                        {        
                                                
                                                
                                                if(icmpnbytes>0)
                                                {
                                                        printf("Got an ICMP packet\n");
                                                        printf("ICMP type:\t%u\n",icmphdr->icmp_type);
                                                        printf("ICMP code:\t%u\n",icmphdr->icmp_code);

                                                        if((icmphdr->icmp_type == 3 && icmphdr->icmp_code ==1) || (icmphdr->icmp_type ==3 && icmphdr->icmp_code ==2) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==3) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==9) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==10) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==13))

                                                        {
                                                                printf("ICMP type:\t%u\n",icmphdr->icmp_type);
                                                                printf("ICMP code:\t%u\n",icmphdr->icmp_code);
                                                                printf("\n Port: %d is filtered\n", port);
                                                        }
                                                        else if(icmphdr->icmp_type == 3)
                                                        printf("The Destination is unreachable\n");
                                                }
                        
                                        }
                                        */
                                        if(nbytes>0)
                                        {
                                                
                                                struct ip *iphrcvd = (struct ip *) buf;
                                                struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));
                                                
                                                if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
                                                {        
                                                        if(ntohs(tcphrcvd->source)==port)
                                                        {
                                                                if ((tcphrcvd->syn==1) && (tcphrcvd->ack==1))
                                                                {
                                                                        printf("SYN SCAN: port %d is open\n",port);
                                                                        tcphddr->syn = 0;
                                                                        tcphddr->rst = 1;
                                                                        sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin));
                                                                        break;
                                                                }
                                                
                                                                else if (tcphrcvd->rst==1)
                                                                {
                                                                        printf("SYN SCAN: port %d is closed\n",port);
                                                                        break;
                                                                }
                                                        

                                                        }
                                                }
                                        }

                                        if(i==99)
                                        {
                                                printf("SYN SCAN: port %d may be open/closed (filtered)\n",port);
                                        }
                                
                                }

                        }                                                            
  if(ackflag==1)
                        {
                                int sock_tcp = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
char packet[4096];
                                struct ip *iphdr = (struct ip *) packet;
                                struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
                                struct sockaddr_in sin;
                                struct sockaddr_storage pin;

                                sin.sin_family = AF_INET;
                                sin.sin_port = htons (port);
                                sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

                                memset (packet, 0, 4096);
                                iphdr->ip_hl = 5;
                                iphdr->ip_v = 4;
                                iphdr->ip_tos = 0;
                                iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
                                iphdr->ip_id = htonl (54321);
                                iphdr->ip_off = 0;
                                iphdr->ip_ttl = 255;
                                iphdr->ip_p = 6;
                                iphdr->ip_sum = 0;
                                iphdr->ip_src.s_addr = inet_addr (finalip);
                                iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

                                tcphddr->source = htons (1235);
                                tcphddr->dest = htons (port);
                                tcphddr->seq = htonl(random ());
                                tcphddr->ack_seq = 0;
                                tcphddr->doff = 5;
                                tcphddr->ack = 1;

                                tcphddr->window = ntohs(65535);
                                tcphddr->check = 0;
                                tcphddr->urg_ptr = 0;

                                struct pseudohdr pseudoheader;
                                memset(&pseudoheader, 0, sizeof(struct pseudohdr));
                                pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
                                pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
                                pseudoheader.padd = 0;
                                pseudoheader.protoNo = IPPROTO_TCP;
                                pseudoheader.length = htons(sizeof(struct tcphdr));
                                memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

                                tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
                                iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

                                int t=1;
                                const int *val = &t;
                                int t_icmp=1;
                                const int *val_icmp = &t_icmp;
                        
                                if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
int i;

                                if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
for (i=0;i<100;i++)
                                {
                                        struct timeval tv;
                                        tv.tv_sec = 2;
                                        tv.tv_usec = 100000;

                                        setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                                        nbytes=0;
                                        memset(buf,0,4096);
                                        int fromlen = sizeof (pin);

                                        nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
if(nbytes>0)
                                        {
                                                struct ip *iphrcvd = (struct ip *) buf;
                                                struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

                                                if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
                                                {
                                                        if(ntohs(tcphrcvd->source)==port)
                                                        {

                                                                if(tcphrcvd->rst==1)
                                                                {
                                                                        printf("ACK SCAN: port %d is unfiltered\n",port);
                                                                        break;
                                                                }
                                                        }
                                                }
                                        }
                                        if(i==99)
                                        {
                                                printf("ACK SCAN: port %d is filtered\n",port);
                                        }
                                }
                        }        
if(finflag==1)
                        {
                                int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
                                char packet[4096];
                                struct ip *iphdr = (struct ip *) packet;
                                struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
                                struct sockaddr_in sin;
                                struct sockaddr_storage pin;

                                sin.sin_family = AF_INET;
                                sin.sin_port = htons (port);
                                sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

                                memset (packet, 0, 4096);
                                iphdr->ip_hl = 5;
                                iphdr->ip_v = 4;
                                iphdr->ip_tos = 0;
                                iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
                                iphdr->ip_id = htonl (54321);
                                iphdr->ip_off = 0;
                                iphdr->ip_ttl = 255;
                                iphdr->ip_p = 6;
                                iphdr->ip_sum = 0;
                                iphdr->ip_src.s_addr = inet_addr (finalip);
                                iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

                                tcphddr->source = htons (1236);
                                tcphddr->dest = htons (port);
                                tcphddr->seq = htonl(random ());
                                tcphddr->ack_seq = 0;
                                tcphddr->doff = 5;
                                tcphddr->fin=1;

                                tcphddr->window = ntohs(65535);
                                tcphddr->check = 0;
                                tcphddr->urg_ptr = 0;

                                struct pseudohdr pseudoheader ;
                                memset(&pseudoheader, 0, sizeof(struct pseudohdr));
                                pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
                                pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
                                pseudoheader.padd = 0;
                                pseudoheader.protoNo = IPPROTO_TCP;
                                pseudoheader.length = htons(sizeof(struct tcphdr));
                                memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

                                tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
                                iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

                                int t=1;
                                const int *val = &t;
                                if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
 int i;

                                if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
for (i=0;i<100;i++)
                                {

                                        struct timeval tv;
                                        tv.tv_sec = 2;
                                        tv.tv_usec = 100000;

                                        setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                                        nbytes=0;
                                        memset(buf,0,4096);
                                        int fromlen = sizeof (pin);

                                        nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
                                        if(nbytes>0)
                                        {
                                                struct ip *iphrcvd = (struct ip *) buf;
                                                struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

                                                if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
                                                {
                                                        if(ntohs(tcphrcvd->source)==port)
                                                        {
                                                                if(tcphrcvd->rst==1)
                                                                {
                                                                        printf("FIN SCAN: port %d is closed\n",port);
                                                                        break;

                                                                }
                                                        }
                                                }
                                        }
                                        if(i==99)
                                        {
                                                printf("FIN SCAN: port %d is open or filtered\n",port);
                                        }
                                }
                        }
if(nullflag==1)
                        {
                                int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
                                char packet[4096];
                                struct ip *iphdr = (struct ip *) packet;
                                struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
                                struct sockaddr_in sin;
                                struct sockaddr_storage pin;

                                sin.sin_family = AF_INET;
                                sin.sin_port = htons (port);
                                sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

                                memset (packet, 0, 4096);
                                iphdr->ip_hl = 5;
                                iphdr->ip_v = 4;
                                iphdr->ip_tos = 0;
                                iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
                                iphdr->ip_id = htonl (54321);
                                iphdr->ip_off = 0;
                                iphdr->ip_ttl = 255;
                                iphdr->ip_p = 6;
                                iphdr->ip_sum = 0;
                                iphdr->ip_src.s_addr = inet_addr (finalip);
                                iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

                                tcphddr->source = htons (1237);
                                tcphddr->dest = htons (port);
                                tcphddr->seq = htonl(random ());
                                tcphddr->ack_seq = 0;
                                tcphddr->doff = 5;

                                tcphddr->window = ntohs(65535);
                                tcphddr->check = 0;
                                tcphddr->urg_ptr = 0;

                                struct pseudohdr pseudoheader ;
                                memset(&pseudoheader, 0, sizeof(struct pseudohdr));
                                pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
                                pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
                                pseudoheader.padd = 0;
                                pseudoheader.protoNo = IPPROTO_TCP;
                                pseudoheader.length = htons(sizeof(struct tcphdr));
                                memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

                                tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
                                iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

                                int t=1;
                                const int *val = &t;
                                if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
 int i;

                                if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
for (i=0;i<100;i++)
                                {

                                        struct timeval tv;
                                        tv.tv_sec = 2;
                                        tv.tv_usec = 100000;

                                        setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                                        nbytes=0;

                                        memset(buf,0,4096);
                                        int fromlen = sizeof (pin);

                                        nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
                                        if(nbytes>0)
                                        {
                                                struct ip *iphrcvd = (struct ip *) buf;
                                                struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));


                                                if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
                                                {
                                                        if(ntohs(tcphrcvd->source)==port)
                                                        {
                                                                if(tcphrcvd->rst==1)
                                                                {
printf("NULL SCAN: port %d is closed\n",port);
                                                                        break;
                                                                }
                                                        }
                                                }
                                        }
                                        if(i==99)
                                        {printf("NULL SCAN: port %d is open or filtered\n",port);
                                        }
                                }
                        }
 if(xmasflag==1)
                        {
                                int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
                                char packet[4096];
                                struct ip *iphdr = (struct ip *) packet;
                                struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
                                struct sockaddr_in sin;
                                struct sockaddr_storage pin;


                                sin.sin_family = AF_INET;
                                sin.sin_port = htons (port);
                                sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

                                memset (packet, 0, 4096);
                                iphdr->ip_hl = 5;
                                iphdr->ip_v = 4;
                                iphdr->ip_tos = 0;
                                iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
                                iphdr->ip_id = htonl (54321);
                                iphdr->ip_off = 0;
                                iphdr->ip_ttl = 255;
                                iphdr->ip_p = 6;
                                iphdr->ip_sum = 0;
                                iphdr->ip_src.s_addr = inet_addr (finalip);
                                iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

                                tcphddr->source = htons (1238);
                                tcphddr->dest = htons (port);
                                tcphddr->seq=htonl(0);
                                tcphddr->ack_seq = 0;
                                tcphddr->doff = 5;
                                tcphddr->urg=1;
                                tcphddr->psh=1;
                                tcphddr->fin=1;

                                tcphddr->window = ntohs(65535);
                                tcphddr->check = 0;
                                tcphddr->urg_ptr = 0;

                                struct pseudohdr pseudoheader ;
                                memset(&pseudoheader, 0, sizeof(struct pseudohdr));
                                pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
                                pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
                                pseudoheader.padd = 0;
                                pseudoheader.protoNo = IPPROTO_TCP;
                                pseudoheader.length = htons(sizeof(struct tcphdr));
                                memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

                                tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
                                iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

                                int t=1;
                                const int *val = &t;
                                if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
int i;

                                if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
for (i=0;i<100;i++)
                                {

                                        struct timeval tv;
                                        tv.tv_sec = 2;
                                        tv.tv_usec = 100000;

                                        setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                                        setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                                        nbytes=0;

                                        memset(buf,0,4096);
                                        int fromlen = sizeof (pin);

                                        nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
                                        if(nbytes>0)
                                        {
                                                struct ip *iphrcvd = (struct ip *) buf;
                                                struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

                                                if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
                                                {
                                                        if(ntohs(tcphrcvd->source)==port)
                                                        {

                                                                if(tcphrcvd->rst==1)
                                                                {
                                                                        printf("XMAS SCAN: port %d is closed\n",port);
                                                                        break;
                                                                }
                                                        }
                                                }
                                        }
                                        if(i==99)
                                        {
                                                printf("XMAS SCAN: port %d is open or filtered\n",port);
                                        }
                                }
                        }
service(ipaddr,port);

}}


