#include "references.h"
#include "headerStructs.h"
void next_protocol_for_ip4(unsigned char *buffer,const unsigned int lenght){
        IP_HDR *ip_hdr = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        switch(ip_hdr->ip_type_prot){
                case IP:
                        decode_eth_hdr(buffer);
                        int ip_header_len = decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int total_header_size1 = ETHER_HEAD_LEN + ip_header_len;
                        showDumpTraffic(buffer, lenght, total_header_size1);
                        break;

                case ICMP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer+ETHER_HEAD_LEN);
                        int icmp_header_len = decode_icmp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size2 = ETHER_HEAD_LEN+sizeof(struct IP_Header) + icmp_header_len;
                        showDumpTraffic(buffer, lenght, total_header_size2);
                        break;
        
                case TCP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int tcp_header_len = decode_tcp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size3 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + tcp_header_len;
                        showDumpTraffic(buffer, lenght, total_header_size3);
                        break;
        
                case UDP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int udp_header_len = decode_udp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size4 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + udp_header_len;
                        showDumpTraffic(buffer, lenght, total_header_size4);
                        break;

                case IGMP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int igmp_header_len = decode_igmp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size5 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + igmp_header_len;
                        showDumpTraffic(buffer, lenght, total_header_size5);
                        break;
        }
        printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}



void if_ARP(unsigned char *buffer, unsigned int lenght){
        decode_eth_hdr(buffer);
        int arp_header_len = decode_arp_hdr(buffer + ETHER_HEAD_LEN);
        int total_header_size = ETHER_HEAD_LEN + arp_header_len;
        showDumpTraffic(buffer, lenght, total_header_size);
        printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}
