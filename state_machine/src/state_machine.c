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

        enum ARP_IP{
	ARP = 0x0806,
	IP4 = 0x0800,
	IP = 0,
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        UDP = 17
	};
	
	unsigned char buffer[DATA_BUFFER_SIZE] = {0};
        for(int i=0;i<5;i++){
		int pack_size=recv(raw_sock_all,buffer,1024,0);
		pcap_t *handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
                char pcap_file_way[128] = {0};
                char y[2] = {0};
                printf("Save dump of packet's data? (y/n) ");
                scanf("%1s",y);
                if(y[0] == 'y' || y[0] == 'Y'){
                        printf("\nEnter the path for pcap-dump(For_example:/dir1/dir2/file.pcap): " );
                        scanf("%s",pcap_file_way);
                        pcap_dumper_t *dumper = pcap_dump_open(handle, pcap_file_way);   
                        struct pcap_pkthdr pcap_hdr;
                        pcap_hdr.caplen = sizeof(buffer);
                        pcap_hdr.len = pcap_hdr.caplen;
                        pcap_dump((unsigned char *)dumper, &pcap_hdr, buffer);
                        pcap_dump_close(dumper);
                }
                if(y[0] == 'n' || y[0] == 'N'){
                        printf("\n\nData won't be saved\n");
                }
		ETHER_HDR *ether_ptr;
                ether_ptr = (ETHER_HDR *)buffer;
		IP_HDR *ip_ptr;
		ip_ptr = (IP_HDR *)buffer;
		ip_ptr = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
		switch(ntohs(ether_ptr->ether_type)){
                        case ARP:
                                STATE_ARP(buffer,pack_size,raw_sock);
				break;
                        
			case IP4:
				switch(ip_ptr->ip_type_prot){
					case IP:
						STATE_IP(buffer,pack_size,raw_sock);	
						break;
					
					case ICMP:
						STATE_ICMP(buffer,pack_size,raw_sock,arg_vector);	
						break;
			
					case TCP:
						STATE_TCP(buffer,pack_size,raw_sock);
						break;

					case UDP:
						STATE_UDP(buffer,pack_size,raw_sock);
						break;

					case IGMP:
						STATE_IGMP(buffer,pack_size,raw_sock);
						break;
					default:
						break;
				}
				break;

			default:
                                break;
                } 
	}
}

