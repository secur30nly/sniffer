#include "references.h"
#include "all_structs.h"
void next_protocol_for_ip4(unsigned char *buffer,const unsigned int lenght){
        IP_HDR *ip_hdr;
        unsigned char *packet_data;
        unsigned int buffer_lenght = lenght;
        unsigned int data_lenght;
        ip_hdr = (IP_HDR *)buffer;
        ip_hdr = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        switch(ip_hdr->ip_type_prot){
                case IP:
                        decode_eth_hdr(buffer);
                        int ip_header_len = decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int total_header_size1 = ETHER_HEAD_LEN + ip_header_len;
                        packet_data = buffer + total_header_size1;
                        data_lenght = buffer_lenght - total_header_size1;
                        if(data_lenght > 0){
                                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                                dumptraffic(packet_data,data_lenght);
                        }
                 
                        else 
                                printf("[*]Данные отсутствуют.\n\v");
                        break;

                case ICMP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer+ETHER_HEAD_LEN);
                        int icmp_header_len = decode_icmp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size2 = ETHER_HEAD_LEN+sizeof(struct IP_Header) + icmp_header_len;
                        packet_data = buffer + total_header_size2;
                        data_lenght = buffer_lenght - total_header_size2;
                        if(data_lenght > 0){
                                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                                dumptraffic(packet_data,data_lenght);
                        }
                 
                        else 
                                printf("[*]Данные отсутствуют.\n\v");           
                        break;
        
                case TCP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int tcp_header_len = decode_tcp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size3 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + tcp_header_len;
                        packet_data = buffer + total_header_size3;
                        data_lenght = buffer_lenght - total_header_size3;
                        if(data_lenght > 0){
                                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                                dumptraffic(packet_data,data_lenght);
                        }
                 
                        else 
                                printf("[*]Данные отсутствуют.\n\v");           
                        break;  
        
                case UDP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int udp_header_len = decode_udp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size4 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + udp_header_len;
                        packet_data = buffer + total_header_size4;
                        data_lenght = buffer_lenght - total_header_size4;
                        if(data_lenght > 0){
                                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                                dumptraffic(packet_data,data_lenght);
                        }
                
                        else 
                                printf("[*]Данные отсутствуют.\n\v");                   
                        break;

                case IGMP:
                        decode_eth_hdr(buffer);
                        decode_ip_hdr(buffer + ETHER_HEAD_LEN);
                        int igmp_header_len = decode_igmp_hdr(buffer + ETHER_HEAD_LEN + sizeof(struct IP_Header));
                        int total_header_size5 = ETHER_HEAD_LEN + sizeof(struct IP_Header) + igmp_header_len;
                        packet_data = buffer + total_header_size5;
                        data_lenght = buffer_lenght - total_header_size5;
                        if(data_lenght > 0){
                                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                                dumptraffic(packet_data,data_lenght);
                        }
                 
                        else 
                                printf("[*]Данные отсутствуют.\n\v");           
                        break;
        }

        printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");

}



void if_ARP(const unsigned char *buffer,const unsigned int lenght){
        const unsigned char *packet_data;
        unsigned int data_lenght;
        unsigned int  buffer_len = lenght;
        decode_eth_hdr(buffer);
        int arp_header_len = decode_arp_hdr(buffer + ETHER_HEAD_LEN);
        int total_header_size6 = ETHER_HEAD_LEN + arp_header_len;
        packet_data = buffer + total_header_size6;
        data_lenght = buffer_len - total_header_size6;
        if(data_lenght > 0 ){
                printf("Был перехвачен payload размером %d байтов:\n\v",data_lenght);
                dumptraffic(packet_data,data_lenght);
        }
        else
                printf("[*]Данные отсутствуют.\n\v");
        printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
}
