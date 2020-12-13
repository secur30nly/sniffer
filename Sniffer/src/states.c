#include "references.h"
#include "headerStructs.h"


void STATE_ICMP(unsigned char *buffer,const unsigned int lenght,int socket,unsigned char **arg_vector){
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer, lenght);
	int check = ether_head_modify(buffer);
	icmp_proto_modify(buffer, lenght, arg_vector);
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);

}

void STATE_ARP(unsigned char *buffer,const unsigned int lenght,int socket){
    if_ARP(buffer, lenght);
    saveInPCAP(buffer, lenght);
    int check = ether_head_modify(buffer);
	arp_proto_modify(buffer + ETHER_HEAD_LEN);
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);

}

void STATE_IP(unsigned char *buffer,const unsigned int lenght,int socket){
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer, lenght);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);

}


void STATE_TCP(unsigned char *buffer,const unsigned int lenght,int socket){
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer, lenght);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);

}

void STATE_UDP(unsigned char *buffer,const unsigned int lenght,int socket){
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer, lenght);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);

}


void STATE_IGMP(unsigned char *buffer,const unsigned int lenght, int socket){
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer, lenght);
    int check = ether_head_modify(buffer);
    struct sockaddr_ll saddr = createSaddr(buffer);
    packetSender(check, buffer, saddr, socket, lenght);
}


