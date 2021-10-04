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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct etherheader *eth = (struct etherheader *)packet;
  static int cntr = 1;
  
  if(ntohs(eth->ether_type) == 0x0800) { //0x0800 is IP type
    struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct etherheader));
    
    int ip_header_len = ip->iph_ihl * 4;//header blocks are 4 bytes
   
    printf("    From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("    To:   %s\n", inet_ntoa(ip->iph_destip));
    
    //determine which protocol
    switch(ip->iph_protocol) {
      case IPPROTO_TCP:
      	printf("Protocol:  TCP\n");
      	return;
      case IPPROTO_UDP:
      	printf("Protocol:  UDP\n");
      	return;
      case IPPROTO_ICMP:
      	printf("Protocol:  ICMP\n");
      	return;
      default:
      	printf("Protocol:  Other\n");
      	return;
    }
  }
  else
    printf("Not, IP: %d\n", cntr++);
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "";//No filter
  bpf_u_int32 net;
  
  //step 1, Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
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
  pcap_loop(handle, -1, got_packet, NULL);
  
  pcap_close(handle);
  return 0;

}
