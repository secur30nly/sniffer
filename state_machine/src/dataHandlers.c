#include "references.h"
#include "all_structs.h"

void dumptraffic(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char byte;
    unsigned int i,j;
    for(i = 0; i < length; i++){
        byte=data_buffer[i];
        printf("%02x ", byte);
        if (((i%16) == 15) || (i == length - 1)){
            printf(" | ");
            for(j = (i - (i%16)); j <= i; j++){
                byte=data_buffer[j];
                if ((byte>31)&&(byte<127))
                    printf("%c",byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}


struct sockaddr_ll createSaddr(){
    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_halen = ETHER_ADDR_LEN;
    memcpy(&saddr.sll_addr,HOST_MAC,6);
    saddr.sll_ifindex = if_nametoindex("wlp7s0");
    return saddr;
}


void saveInPCAP(unsigned char *buffer){
    //Dump of packet's data in "*.pcap" format
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
    char pcap_file_way[128] = {0};
    char y[10];
    printf("Save dump of packet's data? (y/n) ");
    scanf("%1s", y);
    if (y[0] == 'y') {
        printf("\nEnter the path for pcap-dump(For_example:/dir1/dir2/file.pcap): ");
        scanf("%s", pcap_file_way);
        pcap_dumper_t *dumper = pcap_dump_open(handle, pcap_file_way);
        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.caplen = sizeof(buffer);
        pcap_hdr.len = pcap_hdr.caplen;
        pcap_dump((unsigned char *) dumper, &pcap_hdr, buffer);
        pcap_dump_close(dumper);
    } else if (y[0] == 'n') {
        printf("\n\nData won't be saved\n");
    } else {
        printf("\n\nWhat do you mean?\n");
    }
}