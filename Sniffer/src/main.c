#include "references.h"
#include "headerStructs.h"

/*State-Machine*/

int main(int argc,unsigned char *argv[]){
        banner();
        char start[5];
        printf("%s", "Start sniffing?");
        fgets(start, sizeof(start), stdin);
        char *dev, errbuf[PCAP_ERRBUF_SIZE];
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "[-]Couldn't find default device: %s\n", errbuf);
                return(2);
        }
        printf("[+]Sniffing on device: %s\n\n", dev);

        unsigned char **arg_vector = argv;
        int raw_sock_all = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if (raw_sock_all == -1){
                fprintf(stderr, "%s", "Raw-socket error. Maybe try with sudo?\n");
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
        for(int i=0; i < 5; i++){
                int pack_size = recv(raw_sock_all, buffer, 1024, 0);
                ETHER_HDR *ether_ptr = (ETHER_HDR *)buffer;
                IP_HDR *ip_ptr = (IP_HDR *)(buffer + ETHER_HEAD_LEN);
                switch(ntohs(ether_ptr->ether_type)){
                        case ARP:
                                STATE_ARP(buffer, pack_size, raw_sock_all);
                                break;
                        
                        case IP4:
                                switch(ip_ptr->ip_type_prot){
                                        case IP:
                                                STATE_IP(buffer, pack_size, raw_sock_all);
                                                break;

                                        case ICMP:
                                                STATE_ICMP(buffer, pack_size, raw_sock_all, arg_vector);
                                                break;

                                        case TCP:
                                                STATE_TCP(buffer, pack_size, raw_sock_all);
                                                break;

                                        case UDP:
                                                STATE_UDP(buffer, pack_size, raw_sock_all);
                                                break;

                                        case IGMP:
                                                STATE_IGMP(buffer, pack_size, raw_sock_all);
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
