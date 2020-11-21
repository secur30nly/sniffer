#include "references.h"
#include "all_structs.h"

int main(int argc,unsigned char *argv[]){

        char *dev, errbuf[PCAP_ERRBUF_SIZE];
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
        }
        printf("Sniffing on device: %s\n", dev);
   
        unsigned char **arg_vector = argv;
        int raw_sock_all = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if (raw_sock_all == -1){
                printf("%s", "ERROR_ALL\n");
                exit(SADNESS); 
        }

        int raw_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if (raw_sock == -1){
                printf("%s","ERROR_RAW\n");
                exit(SADNESS);
        } 

        //Struct sockaddr_ll for "sendto"
        struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");

        unsigned char buffer[DATA_BUFFER_SIZE] = {0};
        for(int i=0;i<5;i++){
                int pack_size=recv(raw_sock_all,buffer,1024,0);
                ETHER_HDR *general_ptr;
                general_ptr = (ETHER_HDR *)buffer;
                switch(ntohs(general_ptr->ether_type)){
                        case IPv4:
                                next_protocol_for_ip4(buffer,pack_size);
                                break;
                        case ARP:
                                if_ARP(buffer,pack_size);
                                break;
                        default:
                                exit(SADNESS);
                                break;
                }

                //Dump of packet's data in "*.pcap" format
                pcap_t *handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
                char pcap_file_way[128] = {0};
                char y[10];
                printf("Save dump of packet's data? (y/n) ");
                fgets(y,10, stdin);
                if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0) {
                    printf("\nEnter the path for pcap-dump(For_example:/dir1/dir2/file.pcap): ");
                    fgets(pcap_file_way,128, stdin);
                    pcap_dumper_t *dumper = pcap_dump_open(handle, pcap_file_way);
                    struct pcap_pkthdr pcap_hdr;
                    pcap_hdr.caplen = sizeof(buffer);
                    pcap_hdr.len = pcap_hdr.caplen;
                    pcap_dump((unsigned char *) dumper, &pcap_hdr, buffer);
                    pcap_dump_close(dumper);
                } else if (strcmp(y, "n\n") == 0 || strcmp(y, "N\n") == 0) {
                    printf("\n\nData won't be saved\n");
                } else {
                    printf("\n\nWhat do you mean?\n");
                }

                // Modification of packet's headers
                int check = ether_head_modify(buffer);
                printf("\nModify next protocols? (y/n) ");
                modification(buffer,pack_size,arg_vector);
                if_have_tcp_udp(buffer);
                size_t size_mod_buf = sizeof(buffer);

                // Forwarding of modify packet
                if(check == 0){
                    printf("\nSend modified protocol? (y/n) ");
                    char y[10];
                    fgets(y, 10, stdin);
                    if(strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                                ssize_t send_packet = sendto(raw_sock,buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
                                if(send_packet != -1){
                                        printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
                                }

                                else{
                                        printf("%u\n", errno);
                                        printf("%s", strerror(errno));
                                        exit(SADNESS);
                                }
                        }

                        else if (strcmp(y, "y\n") == 0 || strcmp(y, "Y\n") == 0){
                                printf("\nWhy? It's pointless\n");
                        }
                }
        }
        printf("[These are all packets]\n\n");
        return 0;

}
