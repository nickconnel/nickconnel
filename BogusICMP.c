#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct etherheader {
  u_char ether_dhost[6]; //dest addr
  u_char ether_shost[6]; //source addr
  u_short ether_type;    //protocol IP, ARP, RARP, etc..
};

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
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
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

//Assumes that only IP ICMP packets will come here because of filtering
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct etherheader));
  
  const char buffer[1500];
  memset((char *)buffer, 0, 1500); 
  memcpy((char *)buffer, ip, ntohs(ip->iph_len)); //Make copy of incomming ip packet

  int ip_header_len = ip->iph_ihl * 4;//header blocks are 4 bytes 
  struct icmpheader *icmp = (struct icmpheader *) (packet + sizeof(struct etherheader) + ip_header_len);
  int type     = icmp->icmp_type;
  int code     = icmp->icmp_code;

  //if not a echo req. do nothing
  if(type == 8 && code == 0) {
    //Modify type, and adjust checksum of ICMP part
    icmp->icmp_type = 0; //type 8 is echo req. 0 is reply.
    int payload_len = ntohs(ip->iph_len) - sizeof(struct ipheader) - sizeof(struct icmpheader);
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader) + payload_len);
    
    //Swap the source and destination addresses of the IP header
    struct in_addr  iptemp_addr = ip->iph_sourceip;
    ip->iph_sourceip = ip->iph_destip;//These switch around
    ip->iph_destip   = iptemp_addr;
    
    //Send the spoofed packet
    send_raw_ip_packet(ip);
  }
  //else do nothing
}
  
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto \\icmp";//ICMP filter
  bpf_u_int32 net;
  
  //step 1, Open live pcap session on NIC with name enp0s3, lo
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Can't open eth3: %s\n", errbuf);
    exit(1);
  }
  
  //step 2, Compile filter_exp into BPF psuedo-code
  if(pcap_compile(handle, &fp, filter_exp, 0, net)) {
    fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax:  %s\n", filter_exp);
    return -1;
  }
  
  //set the filter
  if (pcap_setfilter(handle, &fp)<0)
  {
    fprintf(stderr, "\nError setting the filter.\n");
    return -1;
  }
  
  //step 3,Capture packets
  int cnt = -1;
  pcap_loop(handle, cnt, got_packet, NULL);// cnt or -1 loops indef
  
  pcap_close(handle);
  return 0;
}
