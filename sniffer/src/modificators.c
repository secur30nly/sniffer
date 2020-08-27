#include "references.h"
#include "all_structs.h"

/*Modification of the protocol header fields for further forwarding (if you need it)*/

void ip_proto_modify(const unsigned char *header_start){
        IP_HDR *ip_header;
        ip_header=(IP_HDR *)header_start;
        printf("[Layer 3 ::: IP-protocol]\n\n");
        printf("___Modify IP-Source's field? (y/n) ");
        char y[10]; 
        scanf("%1s",y);
        printf("\nOld IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_source));
        if (y[0] == 'y'){
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
   
        else {
                printf("[@]Skip\n\n");
        }

        printf("___Modify IP-destination's field? (y/n) ");
        char x[10];
        scanf("%1s",x);
        printf("\nOld IP-Destination: %s\n\n", inet_ntoa(*(struct in_addr*)&ip_header->ip_dest));
        if (x[0] == 'y' ){
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

        else{
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
        scanf("%1s",x);  
        if (x[0] == 'y' ){
                int icmp_header_len = sizeof(ICMP_HDR);
                int total_size_hdr = ETHER_HEAD_LEN+sizeof(IP_HDR) + icmp_header_len;
                unsigned char *only_payload = icmp_buffer + total_size_hdr;
                int payload_len = icmp_pkt_len - total_size_hdr;

                memset(only_payload,0,payload_len);
                only_payload = cmd_vector[1];
                printf("[New Payload]:\n");
                dumptraffic(only_payload,payload_len);
        }
    
        else{
                printf("\nBut why?\n\n");
        }

        printf("########################################################################################################\n\n");
}


int ether_head_modify(const unsigned char *header_start){
        ETHER_HDR *ether_ptr;
        ether_ptr = (ETHER_HDR *)header_start;
        printf("\n[Layer 2 :: Ether-header] Modification MAC-address. Continue? (y/n) ");
        char x[10];
        scanf("%1s",x);  
        if (x[0] == 'y' ){
                printf("Modify source's MAC-address? (y/n) ");
                char y[10];
                scanf("%1s",y);
                if (y[0] == 'y' ){  
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
        else{
                printf("\n[Skip]\n\n"); 
        } 

                printf("\nModify destination's MAC-address? (y/n) ");
                char z[10];
                scanf("%1s",z);
                if (z[0] == 'y'){  
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

                else{
                        printf("\n[Skip]\n\n");
                } 

        printf("\n\n[[Transition to the L3-L4 protocols]]\n\n");
        printf("########################################################################################################\n\n");
        return 0;

        }
 
        else{ 
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
        scanf("%1s",x);  
        if (x[0] == 'y' ){
                printf("\n\n        !!!{Warning: If you upset the condition, the port won't be overwritten correctly}!!!\n\n");
                printf("\n\nOld Port of Source: %hu\n\n", ntohs(tcp_ptr->tcp_src_port));
                printf("[Choose number of Port from 0 to 65535, please]\n");
                unsigned short num_src;
                scanf("%hu", &num_src);
                tcp_ptr->tcp_src_port = htons(num_src);
                printf("\n\nNew Port of Source: %hu\n\n", ntohs(tcp_ptr->tcp_src_port));
        }

       else
                printf("\n[Skip]\n\n");
           
        printf("Modify Port of Destination? (y/n) ");
        char y[10];
        scanf("%1s",y);  
        if (y[0] == 'y' ){
                printf("\n\nOld Port of Destination: %hu\n\n", ntohs(tcp_ptr->tcp_dest_port));
                printf("Choose number of Port from 0 to 65535, please\n");
                unsigned short num_dst;
                scanf("%hu", &num_dst);
                tcp_ptr->tcp_dest_port = htons(num_dst);
                printf("\n\nNew Port of Destination: %hu\n\n", ntohs(tcp_ptr->tcp_dest_port));
        }
       
        else 
                printf("\n[Skip]\n\n");
      
        printf("########################################################################################################\n\n");
}


void udp_proto_modify(const unsigned char *header_start){
        UDP_HDR *udp_ptr;
        udp_ptr = (UDP_HDR *)header_start;
        printf("[Layer 4 :::: (Datagrams)UDP-protocol]\n\n");
        printf("Modify UDP-source port? (y/n) ");
        char button[10];
        scanf("%1s",button);  
        if (button[0] == 'y' ){
                printf("\n\n        !!!{Warning: If you upset the condition, the port won't be overwritten correctly}!!!\n\n");
                printf("\n\nOld Port of Source: %hu\n\n", ntohs(udp_ptr->udp_src_port));
                printf("[Choose number of Port from 0 to 65535, please]\n");
                unsigned short num_src;
                scanf("%hu", &num_src);
                udp_ptr->udp_src_port = htons(num_src);
                printf("\n\nNew Port of Source: %hu\n\n", ntohs(udp_ptr->udp_src_port));
        }

       else
                printf("\n[Skip]\n\n");
           
        printf("Modify UDP-destination port? (y/n) ");
        char butt[10];
        scanf("%1s",butt);  
        if (butt[0] == 'y' ){
                printf("\n\nOld Port of Destination: %hu\n\n", ntohs(udp_ptr->udp_dst_port));
                printf("Choose number of Port from 0 to 65535, please\n");
                unsigned short num_dst;
                scanf("%hu", &num_dst);
                udp_ptr->udp_dst_port = htons(num_dst);
                printf("\n\nNew Port of Destination: %hu\n\n", ntohs(udp_ptr->udp_dst_port));
        }
       
        else 
              printf("\n[Skip]\n\n");
     
        printf("########################################################################################################\n\n");
}



void arp_proto_modify(const unsigned char *header_start){
        ARP_HDR *arp_ptr;
        arp_ptr = (ARP_HDR *)header_start;
        printf("\n[Layer 3 ::: ARP-protocol]\n");
        printf("Modify ARP-packet? (y/n) ");
        char x[10];
        scanf("%1s",x);  
        if (x[0] == 'y' ){
                printf("Mac-address of Source? (y/n) ");
                char y[10];
                scanf("%1s",y);
                if (y[0] == 'y' ){  
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
        else{
                printf("\n[Skip]\n\n"); 
        } 

          
                printf("___Modify field of IP-source? (y/n) ");
                char r[10];
                scanf("%1s",r);
                printf("\nOld IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&arp_ptr->arp_src_ip));
                if (r[0] == 'y'){
                        inet_aton(HOST_IP,(struct in_addr*)&arp_ptr->arp_src_ip);
                        if((inet_aton(HOST_IP,(struct in_addr*)&arp_ptr->arp_src_ip)) == 1){
                                printf("New IP-Source: %s\n\n", inet_ntoa(*(struct in_addr*)&arp_ptr->arp_src_ip));
                        } 
                        else{
                                printf("FAILURE\n");
                                exit(SADNESS);
                        }
                }
   
                else{
                        printf("[@]Skip\n\n");
                }
        printf("########################################################################################################\n\n");
        }

        else 
                printf("\n\n[Skip]\n\n"); 

}

