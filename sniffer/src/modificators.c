#include "references.h"
#include "all_structs.h"

/*Modification of the protocol header fields for further forwarding (if you need it)*/

void ip_proto_modify(const unsigned char *header_start){
        IP_HDR *ip_header;
        ip_header=(IP_HDR *)header_start;
        printf("[Layer 3 ::: IP-protocol]\n\n");
        printf("___Modify IP-Source's field? (y/n) ");
        char y[10];
        fgets(y,10, stdin);
        printf("\nOld IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_source));
        if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                inet_aton(HOST_IP,(struct in_addr*)&ip_header->ip_source);
                if((inet_aton(HOST_IP,(struct in_addr*)&ip_header->ip_source)) == 1){
                        printf("[+]Modification is done!\n");
                        printf("New IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_source));
                }
               
                else{
                        printf("FAILURE\n");
                        exit(SADNESS);
                }
       }
   
        else if (strcmp(y, "n\n") == 0 || strcmp(y, "N\n") == 0){
                printf("[@]Skip\n\n");
        }

        printf("___Modify IP-destination's field? (y/n) ");
        char x[10];
        fgets(x,10, stdin);
        printf("\nOld IP-Destination: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_dest));
        if (strcmp(x, "y\n") == 0 || strcmp(x, "Y\n") == 0){
                inet_aton(HOST_IP,(struct in_addr*)&ip_header->ip_dest);
                if((inet_aton(HOST_IP,(struct in_addr*)&ip_header->ip_dest)) == 1){
                        printf("[+]Modification is done!\n");
                        printf("New IP-Destinaion: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_dest));   
                }

                else{
                        printf("FAILURE\n");
                        exit(SADNESS);
                }
       }

        else if (strcmp(x, "n\n") == 0 || strcmp(x, "N\n") == 0){
                printf("[@]Skip\n\n");
        }


printf("########################################################################################################\n\n");
}


void icmp_proto_modify(unsigned char *buffer,const unsigned int lenght,unsigned char **arg_vctr){
        unsigned char **cmd_vector = arg_vctr;
        unsigned int icmp_pkt_len = lenght;
        unsigned char *icmp_buffer = buffer;  
        printf("[Layer 3 ::: (Service)ICMP-protocol]\n\n");
        printf("Overwrite ICMP-payload? (y/n) ");
        char x[10];
        fgets(x,10, stdin);
        if (strcmp(x, "y\n") == 0 || strcmp(x, "Y\n") == 0){
                int icmp_header_len = sizeof(ICMP_HDR);
                int total_size_hdr = ETHER_HEAD_LEN+sizeof(IP_HDR) + icmp_header_len;
                unsigned char *only_payload = icmp_buffer + total_size_hdr;
                int payload_len = icmp_pkt_len - total_size_hdr;

                memset(only_payload,0,payload_len);
                only_payload = cmd_vector[1];
                printf("[New Payload]:\n");
                dumptraffic(only_payload,payload_len);
        }
    
        else if (strcmp(x, "n\n") == 0 || strcmp(x, "N\n") == 0){
                printf("\nBut why?\n\n");
        }

        printf("########################################################################################################\n\n");
}


int ether_head_modify(const unsigned char *header_start){
        ETHER_HDR *ether_ptr;
        ether_ptr = (ETHER_HDR *)header_start;
        printf("\n[Layer 2 :: Ether-header] Modification MAC-address. Continue? (y/n) ");
        char x[10];
        fgets(x,10, stdin);
        if (strcmp(x, "y\n") == 0 || strcmp(x, "Y\n") == 0){
                printf("Modify source's MAC-address? (y/n) ");
                char y[10];
                fgets(y,10, stdin);
                if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                        printf("\nOld source's MAC-address: %02x",ether_ptr->ether_src_addr[0]);

                        for(int i=1;i<ETHER_ADDR_LEN;i++){
                                printf(":%02x",ether_ptr->ether_src_addr[i]);
                        }

                        printf("\n\n");

                        memset(ether_ptr->ether_src_addr,0,6);
                        memcpy(ether_ptr->ether_src_addr,HOST_MAC,6);

                        printf("New source's MAC-address: %02x",ether_ptr->ether_src_addr[0]);

                        for(int i = 1; i<ETHER_ADDR_LEN; i++){
                                printf(":%02x",ether_ptr->ether_src_addr[i]);
                        }
                
                        printf("\n\n");

                }
                else if (strcmp(y, "n\n") == 0 || strcmp(y, "N\n") == 0){
                        printf("\n[Skip]\n\n");
                }

                printf("\nModify destination's MAC-address? (y/n) ");
                char z[10];
                fgets(z,10, stdin);
                if (strcmp(z, "y\n") == 0 || strcmp(z, "Y\n") == 0){
                        printf("\nOld destination's MAC-address: %02x",ether_ptr->ether_dst_addr[0]);

                        for(int i = 1; i<ETHER_ADDR_LEN; i++){
                                printf(":%02x",ether_ptr->ether_dst_addr[i]);
                        }

                        printf("\n\n");

                        memset(ether_ptr->ether_dst_addr,0,6);
                        memcpy(ether_ptr->ether_dst_addr,HOST_MAC,6);

                        printf("New destination's MAC-address: %02x",ether_ptr->ether_dst_addr[0]);

                        for(int i = 1; i<ETHER_ADDR_LEN; i++){
                                printf(":%02x",ether_ptr->ether_dst_addr[i]);
                        }
                
                        printf("\n\n");

                }

                else if(strcmp(z, "n\n") == 0 || strcmp(z, "N\n") == 0){
                        printf("\n[Skip]\n\n");
                } 

        printf("\n\n[[Transition to the L3-L4 protocols]]\n\n");
        printf("########################################################################################################\n\n");
        return 0;

        }
 
        else if(strcmp(x, "n\n") == 0 || strcmp(x, "N\n") == 0){
                printf("\n\n[[Transition to the L3-L4 protocols]]\n\n");
                return 1;
        }        

}



void tcp_proto_modify(const unsigned char *header_start){
        TCP_HDR *tcp_ptr;
        tcp_ptr = (TCP_HDR *)header_start;
        printf("[Layer 4 :::: (Transport)TCP-protocol]\n\n");
        printf("Modify Port of Source? (y/n) ");
        char x[10];
        fgets(x,10, stdin);
        if (strcmp(x, "y\n") == 0 || strcmp(x, "Y\n") == 0){
                printf("\n\n        !!!{Warning: If you upset the condition, the port won't be overwritten correctly}!!!\n\n");
                printf("\n\nOld Port of Source: %hu\n\n", ntohs(tcp_ptr->tcp_src_port));
                printf("[Choose number of Port from 0 to 65535, please]\n");
                char num_src[10];
                fgets(num_src,10, stdin);
                tcp_ptr->tcp_src_port = htons(atoi(num_src));
                printf("\n\nNew Port of Source: %hu\n\n", ntohs(tcp_ptr->tcp_src_port));
        }

       else if(strcmp(x, "n\n") == 0 || strcmp(x, "N\n") == 0)
                printf("\n[Skip]\n\n");
           
        printf("Modify Port of Destination? (y/n) ");
        char y[10];
        fgets(y,10, stdin);
        if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                printf("\n\nOld Port of Destination: %hu\n\n", ntohs(tcp_ptr->tcp_dest_port));
                printf("Choose number of Port from 0 to 65535, please\n");
                char num_dst[10];
                fgets(num_dst, 10, stdin);
                tcp_ptr->tcp_dest_port = htons(atoi(num_dst));
                printf("\n\nNew Port of Destination: %hu\n\n", ntohs(tcp_ptr->tcp_dest_port));
        }
       
        else if(strcmp(y, "n\n") == 0 || strcmp(y, "N\n") == 0)
                printf("\n[Skip]\n\n");
      
        printf("########################################################################################################\n\n");
}


void udp_proto_modify(const unsigned char *header_start){
        UDP_HDR *udp_ptr;
        udp_ptr = (UDP_HDR *)header_start;
        printf("[Layer 4 :::: (Datagrams)UDP-protocol]\n\n");
        printf("Modify UDP-source port? (y/n) ");
        char button[10];
        fgets(button,10, stdin);
        if (strcmp(button, "y\n") == 0 || strcmp(button, "Y\n") == 0){
                printf("\n\n        !!!{Warning: If you upset the condition, the port won't be overwritten correctly}!!!\n\n");
                printf("\n\nOld Port of Source: %hu\n\n", ntohs(udp_ptr->udp_src_port));
                printf("[Choose number of Port from 0 to 65535, please]\n");
                char num_src[10];
                fgets(num_src,10, stdin);
                udp_ptr->udp_src_port = htons(atoi(num_src));
                printf("\n\nNew Port of Source: %hu\n\n", ntohs(udp_ptr->udp_src_port));
        }

       else if (strcmp(button, "n\n") == 0 || strcmp(button, "N\n") == 0)
                printf("\n[Skip]\n\n");
           
        printf("Modify UDP-destination port? (y/n) ");
        char butt[10];
        fgets(butt,10, stdin);
        if (strcmp(butt, "y\n") == 0 || strcmp(butt, "Y\n") == 0){
                printf("\n\nOld Port of Destination: %hu\n\n", ntohs(udp_ptr->udp_dst_port));
                printf("Choose number of Port from 0 to 65535, please\n");
                char num_dst[10];
                fgets(num_dst, 10, stdin);
                udp_ptr->udp_dst_port = htons(atoi(num_dst));
                printf("\n\nNew Port of Destination: %hu\n\n", ntohs(udp_ptr->udp_dst_port));
        }
       
        else if(strcmp(butt, "n\n") == 0 || strcmp(butt, "N\n") == 0)
              printf("\n[Skip]\n\n");
     
        printf("########################################################################################################\n\n");
}



void arp_proto_modify(const unsigned char *header_start){
        ARP_HDR *arp_ptr;
        arp_ptr = (ARP_HDR *)header_start;
        printf("\n[Layer 3 ::: ARP-protocol]\n");
        printf("Modify ARP-packet? (y/n) ");
        char x[10];
        fgets(x,10, stdin);
        if (strcmp(x, "y\n") == 0 || strcmp(x, "Y\n") == 0){
                printf("Mac-address of Source? (y/n) ");
                char y[10];
                fgets(y,10, stdin);
                if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                        printf("\nOld source's MAC-address: %02x",arp_ptr->arp_src_mac[0]);
                        for(int i=1;i<ETHER_ADDR_LEN;i++){
                                printf(":%02x",arp_ptr->arp_src_mac[i]);
                        }

                         printf("\n\n");
                         memset(arp_ptr->arp_src_mac,0,6);
                         memcpy(arp_ptr->arp_src_mac,HOST_MAC,6);
                         printf("New source's MAC-address: %02x",arp_ptr->arp_src_mac[0]);
                         for(int i=1;i<ETHER_ADDR_LEN;i++){
                                printf(":%02x",arp_ptr->arp_src_mac[i]);
                        }
                                printf("\n\n");

                }
                else if(strcmp(y, "n\n") == 0 || strcmp(y, "N\n") == 0){
                        printf("\n[Skip]\n\n");
                }

          
                printf("___Modify field of IP-source? (y/n) ");
                char r[10];
                fgets(r,10, stdin);
                printf("\nOld IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&arp_ptr->arp_src_ip));
                if (strcmp(r, "y\n") == 0 || strcmp(r, "Y\n") == 0){
                        inet_aton(HOST_IP,(struct in_addr*)&arp_ptr->arp_src_ip);
                        if((inet_aton(HOST_IP,(struct in_addr*)&arp_ptr->arp_src_ip)) == 1){
                                printf("New IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&arp_ptr->arp_src_ip));
                        } 
                        else{
                                printf("FAILURE\n");
                                exit(SADNESS);
                        }
                }
   
                else if(strcmp(r, "n\n") == 0 || strcmp(r, "N\n") == 0){
                        printf("[@]Skip\n\n");
                }
        printf("########################################################################################################\n\n");
        }

        else if(strcmp(x, "n\n") == 0 || strcmp(x, "N\n") == 0)
                printf("\n\n[Skip]\n\n"); 

}

