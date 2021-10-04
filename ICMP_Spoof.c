#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/*Run with root priv.; need -lpcap to compile*/

struct ipheader {
  unsigned char  iph_ihl:4, iph_ver:4; //header len, IP ver
  unsigned char  iph_tos; //Type of service
  unsigned short int  iph_len;
  unsigned short int  iph_ident;
  unsigned short int  iph_flag:3, iph_offset:13;//fragment. flags, offset
  unsigned char  iph_ttl; //time to live
  unsigned char  iph_protocol; //Protocol type
  unsigned short int  iph_chksum; //IP datagram checksum
  struct in_addr  iph_sourceip; //Source IP addr
  struct in_addr  iph_destip;   //Dest. IP addr
};

struct icmpheader {
  unsigned char icmp_type;// type of ICMP packet
  unsigned char icmp_code;// type code, ex. 0,0 echo req. 0,8 reply
  unsigned short int  icmp_chksum; //2-byte CS
  unsigned short int  icmp_id; //used for id request
  unsigned short int  icmp_seq; //sequency num
};

//calc the internet cs (part of checsum.c)
unsigned short in_cksum (unsigned short *buf, int length) {
  unsigned short *w = buf;
  int nleft = length;
  int sum = 0;
  unsigned short temp=0;
  /*
  The alg uses a 32 bit accumulator (sum, adds
  sequential16 bit words to it, and at the end, folds back
  all the early bits from the to 16 bits into the lower 16
  */
  
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2; 
  }
  //treat the odd byte at the end, if any
  if (nleft == 1) {
    *(u_char *)(&temp) = *(u_char *)w;
    sum += temp;
  }
  
  //add back cary outs from top 16 bits to lo 16 bits
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

/*
Given an IP packet, send it out raw socket
the ipheader is as above
*/
void send_raw_ip_packet(struct ipheader *ip) {
  struct sockaddr_in dest_info;
  int enable = 1;
  //step 1. create a raw setwork socket; AF_INET == IPv4
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
  //step 2. Set socket option. REDUNDANT, IPPROTO_RAW implies
  //IP_HDRINCL
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

  //step 3. provide needed info about dest.
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;//for OS if MAC needs to be determined.
  
  //step 4. send the packet out func. ntohs gives length of entire pkt
  if (sendto(sock, ip, ntohs(ip->iph_len), 0/*flags*/, (struct sockaddr *)&dest_info, sizeof(dest_info))<0)
  {
    fprintf(stderr, "\nError sending packet.\n");
    return;
  }

  close(sock);  
}

//Spoof ICMP echo request w/arbitrary addr
int main() {
  char buffer[1500];
  memset(buffer, 0, 1500);
  
  //step1. Fill in the ICMP header
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; //type 8 is echo req. 0 is reply.
  icmp->icmp_code = 0; //code 0 is echo.
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
  
  //step2. fill in the IP header
  char *fraddrstr = "1.2.3.4";
  //char *fraddrstr = "10.0.2.5";
  
  //char *toaddrstr = "10.0.2.4";
  //char *toaddrstr = "8.8.8.8";
  //char *toaddrstr = "10.0.9.5";
  //char *toaddrstr = "10.0.9.1";
  char *toaddrstr = "172.17.0.1";
  //char *toaddrstr = "10.0.2.1";
  //char *toaddrstr = "192.168.0.1";
  struct ipheader *ip = (struct ipheader *) buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr(fraddrstr);
  ip->iph_destip.s_addr = inet_addr(toaddrstr);
  ip->iph_protocol = IPPROTO_ICMP;
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
  
  //step3. Send the spoofed packet
  printf("Attempting to send echo request from: %s\n", fraddrstr);
  printf("                                  to: %s\n", toaddrstr);
  send_raw_ip_packet(ip);
  
  return 0;
}
