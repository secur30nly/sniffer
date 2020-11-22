#include "references.h"
#include "headerStructs.h"

/*Interface to manage protocol header modifications*/

void modification(unsigned char *buffer,const unsigned int lenght,unsigned char **arg_vector){
        char c[10];
        fgets(c, sizeof(c), stdin);
        if (strncmp(c, "n\n", sizeof(c)) == 0){
                printf("\n\n");
                return;
        }

        printf("Choose: {ARP}, {ICMP}(Only payload), {IP}, {UDP}, {TCP}\n");
        char protocol[10];
        fgets(protocol, sizeof(protocol), stdin);
        IP_HDR *ip_header = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        ETHER_HDR *ether_header = (ETHER_HDR *)buffer;
        if(strncmp(protocol,"ARP\n", sizeof(protocol)) == 0){
                if(ntohs(ether_header->ether_type) == ARP){
                        arp_proto_modify(buffer + ETHER_HEAD_LEN);
        }     
                else{
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strncmp(protocol,"IP\n", sizeof(protocol)) == 0){
                if(ntohs(ether_header->ether_type) == IPv4){ 
                        ip_proto_modify(buffer + ETHER_HEAD_LEN);
                }

                else {
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strncmp(protocol,"ICMP\n", sizeof(protocol)) == 0){
                if(ip_header->ip_type_prot == ICMP){
                        icmp_proto_modify(buffer, lenght, arg_vector);
                }
 
                else{
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strncmp(protocol, "UDP\n", sizeof(protocol)) == 0){
                if(ip_header->ip_type_prot == UDP){
                        udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
                } 
 
                else {
                        printf("\n[FAILURE]\n\n");
                        return ;
                }   
        }
        if(strncmp(protocol, "TCP\n", sizeof(protocol)) == 0){
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
        IP_HDR *ip_header = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
        if(ip_header->ip_type_prot == UDP)
                udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));

        if(ip_header->ip_type_prot == TCP)
                tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
}
