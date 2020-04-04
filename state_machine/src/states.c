#include "references.h"
#include "all_structs.h"


void STATE_ICMP(unsigned char *buffer,const unsigned int lenght,int socket,unsigned char **arg_vector){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	int raw_sock = socket;
	unsigned char *icmp_buffer = buffer;
	const unsigned icmp_lenght = lenght;
	unsigned char **icmp_arg_vector = arg_vector;
	next_protocol_for_ip4(icmp_buffer,icmp_lenght);
	int check = ether_head_modify(icmp_buffer);
	icmp_proto_modify(icmp_buffer,icmp_lenght,icmp_arg_vector);
	size_t size_mod_buf = sizeof(icmp_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,icmp_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_ARP(unsigned char *buffer,const unsigned int lenght,int socket){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	int raw_sock = socket;
	const unsigned int arp_lenght = lenght;
	unsigned char *arp_buffer = buffer;
	if_ARP(arp_buffer,arp_lenght);
	int check = ether_head_modify(arp_buffer);
	arp_proto_modify(arp_buffer + ETHER_HEAD_LEN);
	size_t size_mod_buf = sizeof(arp_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,arp_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_IP(unsigned char *buffer,const unsigned int lenght,int socket){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	int raw_sock = socket;
	const unsigned int ip_lenght = lenght;
	unsigned char *ip_buffer = buffer;
	next_protocol_for_ip4(ip_buffer,ip_lenght);
	int check = ether_head_modify(ip_buffer);
	ip_proto_modify(ip_buffer + ETHER_HEAD_LEN);
	size_t size_mod_buf = sizeof(ip_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,ip_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}


void STATE_TCP(unsigned char *buffer,const unsigned int lenght,int socket){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	unsigned char *tcp_buffer = buffer;
	const unsigned int tcp_lenght = lenght;
	int raw_sock = socket;
	next_protocol_for_ip4(tcp_buffer,tcp_lenght);
	int check = ether_head_modify(tcp_buffer);
	ip_proto_modify(tcp_buffer + ETHER_HEAD_LEN);
	tcp_proto_modify(tcp_buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
	size_t size_mod_buf = sizeof(tcp_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,tcp_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_UDP(unsigned char *buffer,const unsigned int lenght,int socket){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	unsigned char *udp_buffer = buffer;
	const unsigned int udp_lenght = lenght;
	int raw_sock = socket;
	next_protocol_for_ip4(udp_buffer,udp_lenght);
	int check = ether_head_modify(udp_buffer);
	ip_proto_modify(udp_buffer + ETHER_HEAD_LEN);
	udp_proto_modify(udp_buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
	size_t size_mod_buf = sizeof(udp_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,udp_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}


void STATE_IGMP(unsigned char *buffer,const unsigned int lenght,int socket){
	struct sockaddr_ll saddr = {0};
        saddr.sll_family = AF_PACKET;
        saddr.sll_protocol = htons(ETH_P_ALL);  
        saddr.sll_halen = ETHER_ADDR_LEN; 
        memcpy(&saddr.sll_addr,HOST_MAC,6);
        saddr.sll_ifindex = if_nametoindex("wlan0");
	unsigned char *igmp_buffer = buffer;
	const unsigned int igmp_lenght = lenght;
	int raw_sock = socket;
	next_protocol_for_ip4(igmp_buffer,igmp_lenght);
	int check = ether_head_modify(igmp_buffer);
	size_t size_mod_buf = sizeof(igmp_buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(raw_sock,igmp_buffer,size_mod_buf,0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf(strerror(errno));
			exit(SADNESS);
		}
	}
}


