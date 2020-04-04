#include "references.h"
#include "all_structs.h"

unsigned int decode_arp_hdr(const unsigned char *begin_header){
        ARP_HDR *arp_header;
        arp_header = (ARP_HDR *)begin_header;
        int arp_header_lenght = sizeof(ARP_HDR);
        printf("\t{:::::ARP-PACKET:::::}\n");
        printf("\tMAC-Type: %hu\t Protocol Type: 0x%x\n",ntohs(arp_header->arp_mac_type),ntohs(arp_header->arp_prot_type));
        printf("\tMAC-Size: %hu\t Protocol Size: %hu\n",arp_header->arp_mac_size,arp_header->arp_prot_size);
        printf("\tMAC-Source: %02x",arp_header->arp_src_mac[0]);
        for(int i = 1; i<ETHER_ADDR_LEN; i++)
                printf(":%02x",arp_header->arp_src_mac[i]);

        printf("\tIP-Source: %s", inet_ntoa(*(struct in_addr*)&arp_header->arp_src_ip)); 
        printf("\n");
        printf("\tMAC-Destination: %02x",arp_header->arp_dst_mac[0]);
        for(int i = 1; i<ETHER_ADDR_LEN; i++)
                printf(":%02x",arp_header->arp_dst_mac[i]);

        printf("\tIP-Destination: %s", inet_ntoa(*(struct in_addr*)&arp_header->arp_dst_ip));

        printf("\n");
        printf("\tCode of Operation: %hu ",ntohs(arp_header->op_code));
        if(ntohs(arp_header->op_code) & 1)
                printf("(ARP-Inquiry)\n\n");
        else    
                printf("(ARP-Answer)\n\n");
        return arp_header_lenght;     
}




void decode_eth_hdr(const unsigned char *begin_header) {
        const struct Ether_Header *ethernet_header;
        ethernet_header = (const struct Ether_Header *)begin_header;
        printf("[[Layer 2 :: Ethernet header]]\n");
        printf("[Source: %02x",ethernet_header->ether_src_addr[0]);
        for(int i = 1; i<ETHER_ADDR_LEN; i++)
                printf(":%02x",ethernet_header->ether_src_addr[i]);
      
        printf("\tDest: %02x",ethernet_header->ether_dst_addr[0]);
        for(int i = 1; i<ETHER_ADDR_LEN; i++)
                printf(":%02x",ethernet_header->ether_dst_addr[i]);

        printf("\t\tType in HEX: 0x%x", ntohs(ethernet_header->ether_type));
        switch (ntohs(ethernet_header->ether_type)){
                case IPv4:
                        printf("(IPv4) ]\n\n");
                        break;
                case ARP:
                        printf("(ARP) ]\n\n");
                        break;
                case WAKE_ON_LAN:
                        printf("(Wake-on-lan) ]\n\n");
                        break; 
                case RARP:
                        printf("(RARP) ]\n\n");
                        break;
                case AARP:
                        printf("(AARP) ]\n\n");
                        break;
                case VLAN_TAGGED:
                        printf("(VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq)");
                        break;
                case IPx:
                        printf("(IPx) ]\n\n");
                        break;
                case IPv6:
                        printf("(IPv6) ]\n\n");
                        break;
                case VLAN_DOUBLE_TAGGED:
                        printf("(VLAN-tagged (IEEE 802.1Q) frame with double tagging) ]\n\n");
                        break;
                default:
                        printf("(Неизвестный протокол) ]\n\n");
                        break;
        }
}



unsigned int decode_ip_hdr(const unsigned char *begin_header){ 
        const struct IP_Header *ip_header;
        ip_header = (const struct IP_Header *)begin_header; 
        size_t size_ip_header= ip_header->ip_ihl * 4;    
        printf("\t((Layer3 ::: IP-Header))\n");  
        printf("\t(IP-version: %u\tIHL: %u\n", ip_header->ip_ver,ip_header->ip_ihl);
        printf("\tSource: %s\t", inet_ntoa(*(struct in_addr*)&ip_header->ip_source));          
        printf("Dest: %s\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_dest));
        printf("\tID: %hu\t",ntohs(ip_header->ip_id));
        printf("\tLenght: %hu\n",ntohs(ip_header->ip_len));
        printf("\tTTL: %u\t", ip_header->ip_ttl);
        printf("\tFlags:\t");
        if(ntohs(ip_header->ip_off) & IP_DF)
                printf("DF\n");
        if(ntohs(ip_header->ip_off) & IP_MF)
                printf("MF\n");
        printf("\tType protocol: %u",ip_header->ip_type_prot);
        switch(ip_header->ip_type_prot){ 
                case IP:
                        printf("(IP)\n\n");
                        break;
                 
                case ICMP:
                        printf("(ICMP)\n\n");
                        break;
                  
                case IGMP:
                        printf("(IGMP)\n\n");
                        break;

                case TCP:
                        printf("(TCP)\n\n");
                        break;
                 
                case UDP:
                        printf("(UDP)\n\n");
                        break;

                default:
                        printf("(Other protocol)\n\n");
                        break;
        }

        return size_ip_header;
}


unsigned int decode_tcp_hdr(const unsigned char *begin_header){
        const struct TCP_Header *tcp_header;
        tcp_header = (const struct TCP_Header *)begin_header;   
        unsigned int size_tcp_header = 4 * (tcp_header->tcp_offset);     
        printf("{{Layer 4 :::: TCP Header}}\n");
        printf("{SRC port: %hu\t", ntohs(tcp_header->tcp_src_port));
        printf("Dest port: %hu\n", ntohs(tcp_header->tcp_dest_port));
        printf("Seq: %u\t\t", ntohl(tcp_header->tcp_seq));
        printf("Ack: %u\n", ntohl(tcp_header->tcp_ack));
        printf("TCP header-size: %u\t Tcp-window: %u\n",size_tcp_header, ntohs(tcp_header->tcp_window));
        printf("TCP-urgent: %u\n", ntohs(tcp_header->tcp_urgent));
        printf("Flags:\t");
        if(tcp_header->tcp_flags & TCP_FIN)
                printf("FIN ");
        if(tcp_header->tcp_flags & TCP_RST)
                printf("RST ");
        if(tcp_header->tcp_flags & TCP_SYN)
                printf("SYN ");
        if(tcp_header->tcp_flags & TCP_PUSH)
                printf("PUSH ");
        if(tcp_header->tcp_flags & TCP_ACK)
                printf("ACK ");
        if(tcp_header->tcp_flags & TCP_URG)
                printf("URG ");
        printf(" }\n\v");
        return size_tcp_header;
}


unsigned int decode_udp_hdr(const unsigned char *begin_header){
        const struct UDP_Header *udp_pointer;
        size_t size_udp_header = sizeof(struct UDP_Header);
        udp_pointer = (const struct UDP_Header *)begin_header;
        printf("{{Layer 4 :::: UDP-Header}}\n");
        printf("(SRC-port: %hu\t DST-port: %hu\n", ntohs(udp_pointer->udp_src_port), ntohs(udp_pointer->udp_dst_port));
        printf("Lenght UDP-header: %hu\n\v", ntohs(udp_pointer->udp_len));
        return size_udp_header;
}


unsigned int decode_igmp_hdr(const unsigned char *begin_header){
        const struct IGMP_Header *igmp_header;
        size_t size_igmp_header = sizeof(struct IGMP_Header);
        igmp_header = (const struct IGMP_Header *)begin_header;
        printf("{{Layer 3 ::: (Service Protocol)IGMP-Header}}\n");
        printf("IGMP Type: %u\t IGMP Code: %u\n",igmp_header->igmp_type,igmp_header->igmp_code);
        printf("IGMP group address: %s\n\v", inet_ntoa(*(struct in_addr*)&igmp_header->igmp_group));
        return size_igmp_header;
}



unsigned int decode_icmp_hdr(const unsigned char *begin_header){
        const struct ICMP_Header *icmp_pointer;
        size_t size_icmp_header = sizeof(struct ICMP_Header); 
        icmp_pointer = (const struct ICMP_Header *)begin_header;                                               
        printf("{{Layer 3 ::: (Service Protocol)ICMP-Header}}\n");
        printf("Sequence: %u\t ID: %u\n", ntohs(icmp_pointer->seq),ntohs(icmp_pointer->id));
        printf("{ICMP Error Type: %x ", icmp_pointer->icmp_type_msg);
        switch(icmp_pointer->icmp_type_msg){
                case ICMP_echoreply:
                        printf("(ECHO REPLY)\n");
                        break;
                case ICMP_DEST_UNREACH:
                        printf("(DESTINATION UNREACHABLE)\n");
                        break;
                case ICMP_SOURCE_QUENCH: 
                        printf("(SOURCE QUENCH)\n");
                        break;
                case ICMP_REDIRECT:
                        printf("(REDIRECT(CHANGE ROUTE))\n");
                        break;  
                case ICMP_ECHO:
                        printf("(ECHO)\n");
                        break;
                case ICMP_TIME_EXCEEDED:
                        printf("(TIME EXCEEDED)\n");
                        break;
                case ICMP_PARAMETERPROB:
                        printf("(PARAMETER PROBLEM)\n");
                        break;
                case ICMP_TIMESTAMP:
                        printf("(TIMESTAMP REQUEST)\n");
                        break;
                case ICMP_TIMESTAMPREPLY:
                        printf("(TIMESTAMP REPLY)\n");
                        break;
                case ICMP_INFO_REQUEST:
                        printf("(Information Request)\n");
                        break;
                case ICMP_INFO_REPLY:
                        printf("(INFO REPLY)\n");
                        break;
                case ICMP_ADDRESS :
                        printf("(ICMP ADDRESS)\n");
                        break;
                case ICMP_ADDRESSREPLY:
                        printf("(ICMP ADDRESS REPLY)\n");
                        break;
                default:
                        printf("U have a problem (:\n");
                        break;
        }

        printf("ICMP code message: %u ",icmp_pointer->icmp_code_msg);
        switch(icmp_pointer->icmp_code_msg){
                case ICMP_NET_UNREACH:
                        printf("(NET UNREACH)\n\n");                  
                        break;
                case ICMP_HOST_UNREACH:
                        printf("(HOST UNREACH)\n\n");
                        break;
                case ICMP_PROT_UNREACH:
                        printf("(PROTOCOL UNREACH)\n\n");
                        break;
                case ICMP_PORT_UNREACH:
                        printf("(PORT UNREACH)\n\n");
                        break;  
                case ICMP_FRAG_NEEDED:
                        printf("(FRAG NEEDED)\n\n");
                        break;
                case ICMP_SR_FAILED:
                        printf("(SR FAILED)\n\n");
                        break;
                case ICMP_NET_UNKNOWN:
                        printf("(NET UNKNOWN)\n\n");
                        break;
                case ICMP_HOST_UNKNOWN:
                        printf("(HOST UNKNOWN)\n\n");
                        break;
                case ICMP_HOST_ISOLATED:
                        printf("(HOST ISOLATED)\n\n");
                        break;
                case ICMP_NET_ANO:
                        printf("(NET ANO)\n\n");
                        break;
                case ICMP_HOST_ANO:
                        printf("(HOST ANO)\n\n");
                        break;
                case ICMP_NET_UNR_TOS:
                        printf("(NET_UNR_TOS)\n\n");
                        break;
                case ICMP_HOST_UNR_TOS:
                        printf("(HOST_UNR_TOS)\n\n");
                        break;
                case ICMP_PKT_FILTERED:
                        printf("(PACKET FILTERED)\n\n");
                        break;
                case ICMP_PREC_VIOLATION:
                        printf("(PREC_VIOLATION)\n\n");
                        break;
                case ICMP_PREC_CUTOFF:
                        printf("(PREC_CUTOFF)\n\n");
                        break;
                default:
                        printf("U have a problem (:\n\n");
                        break;
        }               
        return size_icmp_header;
}
