#include "references.h"
#include "all_structs.h"


void STATE_ICMP(unsigned char *buffer,const unsigned int lenght,int socket,unsigned char **arg_vector){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer);
	int check = ether_head_modify(buffer);
	icmp_proto_modify(buffer, lenght, arg_vector);
    packetSender(check, buffer, saddr, socket);

}

void STATE_ARP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    if_ARP(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	arp_proto_modify(buffer + ETHER_HEAD_LEN);
    packetSender(check, buffer, saddr, socket);

}

void STATE_IP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
    packetSender(check, buffer, saddr, socket);

}


void STATE_TCP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
    packetSender(check, buffer, saddr, socket);

}

void STATE_UDP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
    packetSender(check, buffer, saddr, socket);

}


void STATE_IGMP(unsigned char *buffer,const unsigned int lenght, int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
    packetSender(check, buffer, saddr, socket);
}


