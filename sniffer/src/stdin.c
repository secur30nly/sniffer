#include "references.h"
#include "all_structs.h"

void modification(unsigned char *buffer,const unsigned int lenght,unsigned char **arg_vector){
        unsigned char **arg_vctr = arg_vector;
        const unsigned int packet_len = lenght;
        char c[2];
        unsigned char *packet_buffer = buffer;
        scanf("%1s",c);
        if (c[0] == 'n' ){
                printf("\n\n");
                return;
        }

        printf("Choose: {ARP}, {ICMP}(Only payload), {IP}, {UDP}, {TCP}\n");
        char protocol[10];
        char *ptr= protocol;
        scanf("%s", ptr);
        IP_HDR *ip_header;
        ip_header = (IP_HDR *)buffer;
        ip_header = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        ETHER_HDR *ether_header;
        ether_header = (ETHER_HDR *)buffer;
        if(strcmp(ptr,"ARP") == 0){
                if(ntohs(ether_header->ether_type) == ARP){
                        arp_proto_modify(buffer + ETHER_HEAD_LEN);
        }     
                else{
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strcmp(ptr,"IP") == 0){
                if(ntohs(ether_header->ether_type) == IPv4){ 
                        ip_proto_modify(buffer + ETHER_HEAD_LEN);
                }

                else {
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strcmp(ptr,"ICMP") == 0){
                if(ip_header->ip_type_prot == ICMP){
                        icmp_proto_modify(packet_buffer,packet_len,arg_vctr);
                }
 
                else{
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strcmp(ptr,"UDP") == 0){
                if(ip_header->ip_type_prot == UDP){
                        udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
                } 
 
                else {
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strcmp(ptr,"TCP") == 0){
                if(ip_header->ip_type_prot == TCP){
                        tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
                }
 
                else{
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
}
 
void if_have_tcp_udp(const unsigned char *buffer){
        IP_HDR *ip_header;
        ip_header = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        if(ip_header->ip_type_prot == UDP)
                udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));

        if(ip_header->ip_type_prot == TCP)
                tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
}
