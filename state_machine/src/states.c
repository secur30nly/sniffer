#include "references.h"
#include "all_structs.h"


void STATE_ICMP(unsigned char *buffer,const unsigned int lenght,int socket,unsigned char **arg_vector){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer);
	int check = ether_head_modify(buffer);
	icmp_proto_modify(buffer, lenght, arg_vector);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
            printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_ARP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    if_ARP(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	arp_proto_modify(buffer + ETHER_HEAD_LEN);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_IP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket, buffer,sizeof(buffer),0,(struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}


void STATE_TCP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer,lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	tcp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket ,buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}

void STATE_UDP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	ip_proto_modify(buffer + ETHER_HEAD_LEN);
	udp_proto_modify(buffer + ETHER_HEAD_LEN + sizeof(IP_HDR));
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}


void STATE_IGMP(unsigned char *buffer,const unsigned int lenght,int socket){
    struct sockaddr_ll saddr = createSaddr();
    next_protocol_for_ip4(buffer, lenght);
    saveInPCAP(buffer);
    int check = ether_head_modify(buffer);
	if(check == 0){
		printf("\nSend modified protocol? (y/n) ");
		char y[2];
		scanf("%1s",y);
		ssize_t send_packet = sendto(socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
		if(send_packet != -1){  
			printf("\n]----------------==={PACKET WAS SENT}===----------------[\n\n");
		}
		else{
			printf("%u\n", errno);
			printf("%s", strerror(errno));
			exit(SADNESS);
		}
	}
}


